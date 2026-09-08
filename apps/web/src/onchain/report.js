/** Recompute conservation from confirmed outputs, including reports resumed
 * across a version that did not record per-transaction fees. */
export function accountReport(report) {
  if (!report.funding || !report.transactions.length) return report;
  let input = report.funding.inputValue,
    total = 0;
  for (const tx of report.transactions) {
    const output = tx.outputs.reduce((sum, o) => sum + o.value, 0);
    const fee = input - output;
    if (!Number.isSafeInteger(fee) || fee < 0)
      throw new Error("Confirmed transaction accounting failed");
    tx.fee = fee;
    total += fee;
    input = tx.outputs[0].value;
  }
  report.totalFees = total;
  if (report.ok) report.payouts = report.transactions.at(-1).outputs;
  return report;
}
