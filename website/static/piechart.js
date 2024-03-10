var ctx2 = document.getElementById('doughnuts').getContext('2d');
var doughnut = new Chart(ctx2, {
    type: 'doughnut',
    data: {
        labels: ['Security Threats', 'Normal Traffic'],
        datasets: [{
            label: 'Network Traffic Analysis',
            data: [12, 19],
            backgroundColor: [
                'rgba(255, 99, 132, 0.2)',
                'rgba(54, 162, 235, 0.2)',
            ],
            borderColor: [
                'rgba(255, 99, 132, 1)',
                'rgba(54, 162, 235, 1)'
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