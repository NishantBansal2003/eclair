package fr.acinq.eclair.payment

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import fr.acinq.bitcoin.Bech32

/**
 * Fuzz tests for Bolt 11 invoice deserialization.
 */
class Bolt11InvoiceFuzzTest {

  @FuzzTest(maxDuration = "")
  def fuzzBolt11Invoice(data: FuzzedDataProvider): Unit = {
    // Human-readable part
    val hrp = data.consumeAsciiString(data.consumeInt(1, 83))

    // Data part
    val remaining = data.consumeRemainingAsBytes()
    val int5s: Array[java.lang.Byte] = remaining.map(b => (Math.floorMod(b, 32).toByte): java.lang.Byte)

    // Bech32 encode
    val invoiceStr = try {
      Bech32.encode(hrp, int5s, Bech32.Encoding.Bech32)
    } catch { case _: Exception => return }

    // Deserialize as a Bolt 11 invoice
    val invoice = Bolt11Invoice.fromString(invoiceStr)
    if (invoice.isFailure) return

    // Reserialize
    val encoded = invoice.get.toString

    // Round-trip
    val invoice2 = Bolt11Invoice.fromString(encoded)
    assert(invoice2.isSuccess)
    assert(invoice.get == invoice2.get)
  }
}
