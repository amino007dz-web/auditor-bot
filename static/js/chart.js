function countSeverities(text) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  var re = /^#{2,4}\s*(\*\*)?\s*(Critical|High|Medium|Low|Info)\b/gim;
  var m;
  while ((m = re.exec(text)) !== null) {
    var key = m[2];
    if (key === 'Critical' || key === 'High' || key === 'Medium' || key === 'Low' || key === 'Info') counts[key]++;
  }
  const total = counts.Critical + counts.High + counts.Medium + counts.Low + counts.Info;
  if (total === 0) return '';
  return counts.Critical + 'C ' + counts.High + 'H ' + counts.Medium + 'M ' + counts.Low + 'L ' + counts.Info + 'I';
}

function showChart() {
  el.chartModal.style.display = 'flex';
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  var re = /^#{2,4}\s*(\*\*)?\s*(Critical|High|Medium|Low|Info)\b/gim;
  var m;
  while ((m = re.exec(currentReportText)) !== null) {
    var key = m[2];
    if (key === 'Critical' || key === 'High' || key === 'Medium' || key === 'Low' || key === 'Info') counts[key]++;
  }
  if (chartInstance) { chartInstance.destroy(); chartInstance = null; }
  if (typeof Chart === 'undefined') return;
  chartInstance = new Chart(el.severityChart, {
    type: 'bar',
    data: {
      labels: Object.keys(counts),
      datasets: [{
        label: 'Findings',
        data: Object.values(counts),
        backgroundColor: ['#da3633', '#d29922', '#58a6ff', '#3fb950', '#8b949e'],
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, ticks: { stepSize: 1, color: '#8b949e' }, grid: { color: '#30363d' } },
        x: { ticks: { color: '#8b949e' } }
      }
    }
  });
}
