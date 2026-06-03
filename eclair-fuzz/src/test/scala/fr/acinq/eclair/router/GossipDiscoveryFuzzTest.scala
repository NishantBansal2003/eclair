package fr.acinq.eclair.router

import akka.actor.typed.scaladsl.adapter.actorRefAdapter
import akka.actor.{Actor, ActorContext, ActorSystem, typed}
import akka.event.DiagnosticLoggingAdapter
import akka.testkit.TestActorRef
import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import fr.acinq.bitcoin.scalacompat.Crypto.PrivateKey
import fr.acinq.bitcoin.scalacompat.Crypto
import fr.acinq.bitcoin.scalacompat.Script.{pay2wsh, write}
import fr.acinq.bitcoin.scalacompat.{ByteVector32, SatoshiLong, Transaction, TxId, TxOut}
import fr.acinq.eclair.blockchain.bitcoind.ZmqWatcher
import fr.acinq.eclair.blockchain.bitcoind.ZmqWatcher.{UtxoStatus, ValidateResult}
import fr.acinq.eclair.router.Graph.GraphStructure.DirectedGraph
import fr.acinq.eclair.router.Router._
import fr.acinq.eclair.transactions.Scripts
import fr.acinq.eclair.wire.protocol.{ChannelAnnouncement, ChannelUpdate, ChannelUpdateTlv, Color, NodeAnnouncement, NodeAnnouncementTlv, Tlv, TlvStream}
import fr.acinq.eclair.TestUtils.NoLoggingDiagnostics
import fr.acinq.eclair.{BlockHeight, CltvExpiryDelta, Features, MilliSatoshi, NodeParams, RealShortChannelId, ShortChannelId, TestConstants, TimestampSecond}
import scodec.bits.ByteVector
import scodec.{Attempt, Codec, DecodeResult}

import java.util.concurrent.atomic.AtomicLong
import scala.collection.immutable.SortedMap
import scala.concurrent.duration.DurationLong

/**
 * Fuzz tests for the gossip discovery state machine.
 */
class GossipDiscoveryFuzzTest {

  import GossipDiscoveryFuzzTest._

  private var data: Data = emptyData

  // Channels announced during this run, reused to generate matching channel updates and node announcements.
  private var knownChannels: Vector[ChannelKeys] = Vector.empty

  private def consumePrivateKey(fdp: FuzzedDataProvider): PrivateKey =
    PrivateKey(ByteVector32(ByteVector.view(fdp.consumeBytes(32)).padTo(32)))

  // Maximum values of fixed-width protocol fields, matching their wire codecs.
  private val maxUint16: Int = 0xffff
  private val maxUint24: Int = 0xffffff
  private val maxUint32: Long = 0xffffffffL
  private val maxMillisatoshi: Long = Long.MaxValue

  // Keep the output index small: makeFundingTx fills one output per index, so a random index would build huge txs.
  private def consumeRealScid(fdp: FuzzedDataProvider): RealShortChannelId =
    RealShortChannelId(BlockHeight(fdp.consumeLong(0, maxUint24)), fdp.consumeInt(0, maxUint24), fdp.consumeInt(0, 10))

  private def consumeTimestamp(fdp: FuzzedDataProvider): TimestampSecond =
    if (fdp.consumeBoolean()) {
      // Half the time, use a timestamp relative to now.
      TimestampSecond.now() - fdp.consumeLong(0, 20.days.toSeconds)
    } else {
      // The other half, let the fuzzer pick any valid timestamp.
      TimestampSecond(fdp.consumeLong(0, maxUint32))
    }

  private def makeFundingTx(chanAnn: ChannelAnnouncement, fundingOutput: TxOut): Transaction = {
    val outputIndex = ShortChannelId.coordinates(chanAnn.shortChannelId).outputIndex
    Transaction(version = 2, txIn = Nil, txOut = Seq.fill(outputIndex)(TxOut(0.sat, ByteVector.empty)) :+ fundingOutput, lockTime = 0)
  }

  private def consumeTlvStream[T <: Tlv](fdp: FuzzedDataProvider, codec: Codec[TlvStream[T]]): TlvStream[T] =
    if (fdp.consumeBoolean()) {
      TlvStream.empty[T]
    } else {
      val tlvLen = fdp.consumeInt(0, maxUint16)
      codec.decode(ByteVector.view(fdp.consumeBytes(tlvLen)).bits) match {
        case Attempt.Successful(DecodeResult(stream, _)) => stream
        case Attempt.Failure(_) => TlvStream.empty[T]
      }
    }

  @FuzzTest(maxDuration = "")
  def fuzzGossipDiscovery(fdp: FuzzedDataProvider): Unit = {
    data = emptyData
    knownChannels = Vector.empty
    blockHeight.set(TestConstants.defaultBlockHeight)
    while (fdp.remainingBytes() > 0) {
      fdp.consumeInt(0, 6) match {
        case 0 =>
          // Handle a channel announcement.
          val scid = consumeRealScid(fdp)
          val fLen = fdp.consumeInt(0, maxUint16)
          val features = Features(ByteVector.view(fdp.consumeBytes(fLen)))
          val senderKey = consumePrivateKey(fdp)
          val nodeKey1 = consumePrivateKey(fdp)
          val nodeKey2 = consumePrivateKey(fdp)
          val fundingKey1 = consumePrivateKey(fdp)
          val fundingKey2 = consumePrivateKey(fdp)
          if (Seq(senderKey, nodeKey1, nodeKey2, fundingKey1, fundingKey2).forall(_.isValid)) {
            val witness = Announcements.generateChannelAnnouncementWitness(chainHash, scid, nodeKey1.publicKey, nodeKey2.publicKey, fundingKey1.publicKey, fundingKey2.publicKey, features)
            val chanAnn = ChannelAnnouncement(
              nodeSignature1 = Announcements.signChannelAnnouncement(witness, nodeKey1),
              nodeSignature2 = Announcements.signChannelAnnouncement(witness, nodeKey2),
              bitcoinSignature1 = Announcements.signChannelAnnouncement(witness, fundingKey1),
              bitcoinSignature2 = Announcements.signChannelAnnouncement(witness, fundingKey2),
              features = features,
              chainHash = chainHash,
              shortChannelId = scid,
              nodeId1 = nodeKey1.publicKey,
              nodeId2 = nodeKey2.publicKey,
              bitcoinKey1 = fundingKey1.publicKey,
              bitcoinKey2 = fundingKey2.publicKey
            )
            val origin = RemoteGossip(system.deadLetters, senderKey.publicKey)
            data = Validation.handleChannelAnnouncement(data, watcher, origin, chanAnn)
            // Remember this channel's keys so we can later send matching channel updates and node announcements.
            knownChannels = knownChannels :+ ChannelKeys(scid, nodeKey1, nodeKey2)
          }
        case 1 =>
          // Handle a UTXO lookup.
          val awaiting = data.awaiting.keys.toIndexedSeq
          if (awaiting.nonEmpty) {
            val chanAnn = awaiting(fdp.consumeInt(0, awaiting.size - 1))
            val fundingAmount = fdp.consumeLong(1L, 1_00000000L).sat
            val fundingScript = write(pay2wsh(Scripts.multiSig2of2(chanAnn.bitcoinKey1, chanAnn.bitcoinKey2)))
            val fundingTx: Either[Throwable, (Transaction, UtxoStatus)] = fdp.consumeInt(0, 3) match {
              case 0 =>
                // The funding output is a valid 2-of-2 and is unspent: the channel is accepted.
                Right((makeFundingTx(chanAnn, TxOut(fundingAmount, fundingScript)), UtxoStatus.Unspent))
              case 1 =>
                // The funding output is present but uses an unexpected script: the announcement is rejected as invalid.
                val invalidScript = ByteVector.view(fdp.consumeBytes(fdp.consumeInt(0, 100)))
                Right((makeFundingTx(chanAnn, TxOut(fundingAmount, invalidScript)), UtxoStatus.Unspent))
              case 2 =>
                // The funding output has already been spent: the channel is closed (or being closed).
                Right((makeFundingTx(chanAnn, TxOut(fundingAmount, fundingScript)), UtxoStatus.Spent(spendingTxConfirmed = fdp.consumeBoolean())))
              case _ =>
                // The lookup itself failed (e.g. the funding transaction couldn't be retrieved).
                Left(new RuntimeException("validation failed"))
            }
            data = Validation.handleChannelValidationResponse(data, nodeParams, watcher, ValidateResult(chanAnn, fundingTx))
          }
        case 2 =>
          // Handle a channel update.
          // Half the time reuse a known channel (matched + signed by the right side), otherwise use random values.
          val (scid, nodeKey, isNode1) = if (knownChannels.nonEmpty && fdp.consumeBoolean()) {
            val channel = knownChannels(fdp.consumeInt(0, knownChannels.size - 1))
            val isNode1 = fdp.consumeBoolean()
            (channel.scid, if (isNode1) channel.nodeKey1 else channel.nodeKey2, isNode1)
          } else {
            (consumeRealScid(fdp), consumePrivateKey(fdp), fdp.consumeBoolean())
          }
          val timestamp = consumeTimestamp(fdp)
          val messageFlags = ChannelUpdate.MessageFlags(dontForward = fdp.consumeBoolean())
          val channelFlags = ChannelUpdate.ChannelFlags(isEnabled = fdp.consumeBoolean(), isNode1 = isNode1)
          val cltvExpiryDelta = CltvExpiryDelta(fdp.consumeInt(0, maxUint16))
          val htlcMinimumMsat = MilliSatoshi(fdp.consumeLong(0, maxMillisatoshi))
          val feeBaseMsat = MilliSatoshi(fdp.consumeLong(0, maxUint32))
          val feeProportionalMillionths = fdp.consumeLong(0, maxUint32)
          val htlcMaximumMsat = MilliSatoshi(fdp.consumeLong(0, maxMillisatoshi))
          val tlvStream = consumeTlvStream(fdp, ChannelUpdateTlv.channelUpdateTlvCodec)
          val senderKey = consumePrivateKey(fdp)
          if (Seq(senderKey, nodeKey).forall(_.isValid)) {
            val witness = Announcements.channelUpdateWitnessEncode(chainHash, scid, timestamp, messageFlags, channelFlags, cltvExpiryDelta, htlcMinimumMsat, feeBaseMsat, feeProportionalMillionths, htlcMaximumMsat, tlvStream)
            val chanUpd = ChannelUpdate(
              signature = Crypto.sign(witness, nodeKey),
              chainHash = chainHash,
              shortChannelId = scid,
              timestamp = timestamp,
              messageFlags = messageFlags,
              channelFlags = channelFlags,
              cltvExpiryDelta = cltvExpiryDelta,
              htlcMinimumMsat = htlcMinimumMsat,
              feeBaseMsat = feeBaseMsat,
              feeProportionalMillionths = feeProportionalMillionths,
              htlcMaximumMsat = htlcMaximumMsat,
              tlvStream = tlvStream
            )
            val origin = RemoteGossip(system.deadLetters, senderKey.publicKey)
            data = Validation.handleChannelUpdate(data, nodeParams.db.network, nodeParams.currentBlockHeight, Right(RemoteChannelUpdate(chanUpd, Set(origin))))
          }
        case 3 =>
          // Handle a node announcement.
          val timestamp = consumeTimestamp(fdp)
          val fLen = fdp.consumeInt(0, maxUint16)
          val features = Features(ByteVector.view(fdp.consumeBytes(fLen)))
          val color = Color(fdp.consumeByte(), fdp.consumeByte(), fdp.consumeByte())
          val alias = fdp.consumeAsciiString(32)
          val tlvStream = consumeTlvStream(fdp, NodeAnnouncementTlv.nodeAnnouncementTlvCodec)
          val senderKey = consumePrivateKey(fdp)
          // Half the time reuse a known channel's node.
          val nodeKey = if (knownChannels.nonEmpty && fdp.consumeBoolean()) {
            val channel = knownChannels(fdp.consumeInt(0, knownChannels.size - 1))
            if (fdp.consumeBoolean()) channel.nodeKey1 else channel.nodeKey2
          } else {
            consumePrivateKey(fdp)
          }
          if (Seq(senderKey, nodeKey).forall(_.isValid)) {
            val witness = Announcements.nodeAnnouncementWitnessEncode(timestamp, nodeKey.publicKey, color, alias, features, Nil, tlvStream)
            val nodeAnn = NodeAnnouncement(
              signature = Crypto.sign(witness, nodeKey),
              features = features,
              timestamp = timestamp,
              nodeId = nodeKey.publicKey,
              rgbColor = color,
              alias = alias,
              addresses = Nil,
              tlvStream = tlvStream
            )
            val origin = RemoteGossip(system.deadLetters, senderKey.publicKey)
            data = Validation.handleNodeAnnouncement(data, nodeParams.db.network, Set(origin), nodeAnn)
          }
        case 4 =>
          // Mine new blocks.
          blockHeight.addAndGet(fdp.consumeLong(0, 2016))
        case 5 =>
          // Prune stale channels.
          data = StaleChannels.handlePruneStaleChannels(data, nodeParams.db.network, nodeParams.currentBlockHeight)
        case 6 =>
          // A channel's funding transaction was spent.
          val channelIds = (data.channels.keys ++ data.prunedChannels.keys).toIndexedSeq
          if (channelIds.nonEmpty) {
            val scid = channelIds(fdp.consumeInt(0, channelIds.size - 1))
            val spendingTxId_opt = if (fdp.consumeBoolean()) Some(TxId(ByteVector32(ByteVector.view(fdp.consumeBytes(32)).padTo(32)))) else None
            data = Validation.handleChannelSpent(data, watcher, nodeParams.db.network, spendingTxId_opt, Set(scid))
          }
      }
    }
  }

}

object GossipDiscoveryFuzzTest {

  /** The keys used to announce a channel, kept so that we can generate matching channel updates and node announcements. */
  private case class ChannelKeys(scid: RealShortChannelId, nodeKey1: PrivateKey, nodeKey2: PrivateKey)

  // Single actor system shared across all fuzz iterations; implicit so the testkit constructs below resolve it.
  private implicit lazy val system: ActorSystem = ActorSystem("gossip-fuzz")

  private val blockHeight = new AtomicLong(TestConstants.defaultBlockHeight)
  // Wired to the shared blockHeight so that case 4 (mining) advances nodeParams.currentBlockHeight.
  private lazy val nodeParams: NodeParams = TestConstants.Alice.nodeParams.copy(blockHeight = blockHeight)
  private lazy val chainHash = nodeParams.chainHash
  // Dummy actor that only exists to provide the implicit ActorContext the gossip handlers require.
  private lazy val holder = TestActorRef(new Actor {
    override def receive: Receive = { case _ => () }
  })
  // Watch/validate requests are discarded; the fuzzer supplies validation responses directly (case 1).
  private lazy val watcher: typed.ActorRef[ZmqWatcher.Command] = actorRefAdapter(system.deadLetters)

  private implicit lazy val ctx: ActorContext = holder.underlyingActor.context
  private implicit lazy val log: DiagnosticLoggingAdapter = NoLoggingDiagnostics

  // Router state with everything empty: the fuzzer builds it up from scratch on each run.
  private def emptyData: Data = Data(
    Map.empty, SortedMap.empty, SortedMap.empty,
    Stash(Map.empty, Map.empty),
    rebroadcast = Rebroadcast(channels = Map.empty, updates = Map.empty, nodes = Map.empty),
    awaiting = Map.empty,
    privateChannels = Map.empty,
    scid2PrivateChannels = Map.empty,
    excludedChannels = Map.empty,
    graphWithBalances = GraphWithBalanceEstimates(DirectedGraph(), nodeParams.routerConf.balanceEstimateHalfLife),
    sync = Map.empty,
    spentChannels = Map.empty)
}
