var ctx = document.getElementById('lineChart').getContext('2d');
var myChart;

// Function to update the chart with new data
function updateChart(labels, data) {
    if (myChart) {
        myChart.destroy();  // Destroy the existing chart to avoid conflicts
    }

    myChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Trend of Network Traffic',
                data: data,
                backgroundColor: ['rgba(85, 85, 85, 1)'],
                borderColor: 'rgb(41, 155, 99)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true
        }
    });
}

// Function to fetch data from the server
function fetchDataAndUpdateChart() {
    // Make an AJAX request to fetch data from the server
    $.ajax({
        url: '/get_last_12_entries/',  // Update the URL based on your Django URL pattern
        method: 'GET',
        success: function (data) {
            // Extract labels and data from the response
            var labels = data.labels;
            var chartData = data.chart_data;

            // Update the chart with new data
            updateChart(labels, chartData);
        },
        error: function (error) {
            console.log('Error fetching data:', error);
        }
    });
}

// Call the fetchDataAndUpdateChart function when the document is ready
$(document).ready(function () {
    fetchDataAndUpdateChart();
    // Set an interval to refresh the chart every 5 seconds
    setInterval(fetchDataAndUpdateChart, 5000);
});
