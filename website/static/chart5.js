var ctx2 = document.getElementById('doughnut').getContext('2d');
var doughnut = new Chart(ctx2, {
    type: 'doughnut',
    data: {
        labels: ['Anomaly', 'Normal Traffic'],
        datasets: [{
            label: 'Network Traffic Analysis',
            data: [12, 19],
            backgroundColor: [
                'rgba(255, 206, 86, 0.2)',
                'rgba(75, 192, 192, 0.2)',
            ],
            borderColor: [
                'rgba(255, 206, 86, 1)',
                'rgba(75, 192, 192, 1)'
            ],
            borderWidth: 1
        }]
    },
    options: {
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});