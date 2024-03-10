

var ctx = document.getElementById('lineChart').getContext('2d');
var labels = {{ labels|safe }};
var chartData = {{ chart_data|safe }};
var myChart = new Chart(ctx, {
type: 'line',
data: {
    labels:  ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L'],
    datasets: [{
        label: 'Trend of Network Traffic',
        data: chartData,
        backgroundColor: [
            'rgba(85,85,85, 1)'

        ],
        borderColor: 'rgb(41, 155, 99)',

        borderWidth: 1
    }]
},
options: {
    responsive: true
}
});
createChart();