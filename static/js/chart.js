function countSeverities(text) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  var re = /^#{2,4}\s*(\*\*)?\s*(Critical|High|Medium|Low|Info)\b/gim;
  var m;
  while ((m = re.exec(text)) !== null) {
    var key = m[2];
    if (counts.hasOwnProperty(key)) counts[key]++;
  }
  const total = counts.Critical + counts.High + counts.Medium + counts.Low + counts.Info;
  if (total === 0) return '';
  return counts.Critical + 'C ' + counts.High + 'H ' + counts.Medium + 'M ' + counts.Low + 'L ' + counts.Info + 'I';
}

function showChart() {
  if (!currentReportText) return;
  el.chartModal.classList.add('open');
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  var re = /^#{2,4}\s*(\*\*)?\s*(Critical|High|Medium|Low|Info)\b/gim;
  var m;
  while ((m = re.exec(currentReportText)) !== null) {
    var key = m[2];
    if (counts.hasOwnProperty(key)) counts[key]++;
  }
  if (chartInstance) { chartInstance.destroy(); chartInstance = null; }
  if (typeof Chart === 'undefined') return;
  const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
  chartInstance = new Chart(el.severityChart, {
    type: 'bar',
    data: {
      labels: Object.keys(counts),
      datasets: [{
        label: 'Findings',
        data: Object.values(counts),
        backgroundColor: ['#da3633', '#d29922', '#58a6ff', '#3fb950', '#8b949e'],
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, ticks: { stepSize: 1, color: isDark ? '#8b949e' : '#656d76' }, grid: { color: isDark ? '#30363d' : '#d0d7de' } },
        x: { ticks: { color: isDark ? '#8b949e' : '#656d76' } },
      }
    }
  });
}
