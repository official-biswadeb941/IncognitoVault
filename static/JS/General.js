//JS Code for the Gauges in Dashboard
let cpuGauge, memoryGauge, swapGauge, diskGauge, uploadGauge, downloadGauge, pingGauge;

function initializeGauges() {
    if (typeof JustGage !== 'undefined') {
        cpuGauge = createGauge("cpu-meter", "CPU Usage");
        memoryGauge = createGauge("memory-meter", "Memory Usage");
        swapGauge = createGauge("swap-meter", "Swap Usage");
        diskGauge = createGauge("disk-meter", "Disk Usage");
        uploadGauge = createGauge("upload-meter", "Upload Speed", "Mbps");
        downloadGauge = createGauge("download-meter", "Download Speed", "Mbps");
        pingGauge = createGauge("ping-meter", "Ping Latency", "ms");
    } else {
        console.error("JustGage is not defined. Please check the script loading.");
    }
}

function createGauge(id, title, unit = "%") {
    return new JustGage({
        id,
        value: 0,
        min: 0,
        max: 100,
        title,
        label: unit,
        levelColors: ["#FF5733", "#FFC300", "#28B463"],
        pointer: true,
        gaugeWidthScale: 0.5,
        relativeGaugeSize: true,
        labelFontColor: "#FFFFFF",
        valueFontColor: "#FFFFFF",
        valueFontSize: 25,  // ⬅️ Increase size of center text (default is 16-20)
        valueFontWeight: "bold", // ⬅️ Make the center value bold
        donut: true,
        pointerOptions: { color: "#2C3E50", strokeWidth: 4 },
        animationSpeed: 300 // Slower animation for smooth transitions
    });
}

function smoothUpdateGauge(gauge, newValue) {
    if (!gauge) return;
    let currentValue = gauge.config.value;
    let step = (newValue - currentValue) / 20; // Break update into smaller steps
    let count = 0;
    function animate() {
        if (count < 20) {
            currentValue += step;
            gauge.refresh(Math.round(currentValue * 100) / 100);
            count++;
            requestAnimationFrame(animate); // Use requestAnimationFrame for smooth animation
        } else {
            gauge.refresh(newValue);
        }
    }
    animate();
}

function updateLEDIndicator(ledId, status) {
    const led = document.getElementById(ledId);
    if (led) {
        if (status.includes('Connected')) {
            // Add the 'green' class to make it green and pulsing
            led.classList.add('green');
            led.classList.remove('red');
        } else {
            // Add the 'red' class to make it red and pulsing
            led.classList.add('red');
            led.classList.remove('green');
        }
    }
}

async function fetchHealthData() {
    try {
        const response = await fetch('/health');
        const healthData = await response.json();

        // Safe parsing function to prevent errors
        function parseValue(data, key) {
            return data[key] && typeof data[key] === 'string' ? parseFloat(data[key].split(' ')[0]) || 0 : 0;
        }
        smoothUpdateGauge(cpuGauge, parseValue(healthData, 'cpu_usage'));
        smoothUpdateGauge(memoryGauge, parseValue(healthData, 'memory_usage'));
        smoothUpdateGauge(swapGauge, parseValue(healthData, 'swap_usage'));
        smoothUpdateGauge(diskGauge, parseValue(healthData, 'disk_usage'));
        smoothUpdateGauge(uploadGauge, parseValue(healthData, 'upload_speed'));
        smoothUpdateGauge(downloadGauge, parseValue(healthData, 'download_speed'));
        smoothUpdateGauge(pingGauge, parseValue(healthData, 'ping_latency'));
        if (healthData.redis_status) {
            updateLEDIndicator('redis-led', healthData.redis_status);
        }
        if (healthData.mysql_status) {
            updateLEDIndicator('mysql-led', healthData.mysql_status);
        }

    } catch (error) {
        console.error('Error fetching health data:', error);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    initializeGauges();
    fetchHealthData();
    setInterval(fetchHealthData, 1500); // Fetch every 1.5 seconds
});
