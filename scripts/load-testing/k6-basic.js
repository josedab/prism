// k6 load testing script for Prism
// Run: k6 run scripts/load-testing/k6-basic.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const latency = new Trend('latency');

// Test configuration
export const options = {
    // Scenarios
    scenarios: {
        // Smoke test
        smoke: {
            executor: 'constant-vus',
            vus: 1,
            duration: '10s',
            startTime: '0s',
        },
        // Load test
        load: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '30s', target: 50 },   // Ramp up
                { duration: '1m', target: 50 },    // Stay at peak
                { duration: '30s', target: 0 },    // Ramp down
            ],
            startTime: '10s',
        },
        // Stress test
        stress: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '30s', target: 100 },
                { duration: '1m', target: 200 },
                { duration: '30s', target: 300 },
                { duration: '1m', target: 300 },
                { duration: '30s', target: 0 },
            ],
            startTime: '2m30s',
        },
    },

    // Thresholds
    thresholds: {
        http_req_duration: ['p(95)<500', 'p(99)<1000'],  // 95% under 500ms
        http_req_failed: ['rate<0.01'],                  // Error rate under 1%
        errors: ['rate<0.01'],
    },
};

// Configuration
const BASE_URL = __ENV.PRISM_URL || 'http://localhost:8080';

// Test endpoints
const endpoints = [
    { path: '/', method: 'GET', weight: 40 },
    { path: '/api/health', method: 'GET', weight: 20 },
    { path: '/api/users', method: 'GET', weight: 20 },
    { path: '/api/data', method: 'POST', weight: 15 },
    { path: '/api/status', method: 'GET', weight: 5 },
];

// Weighted random selection
function selectEndpoint() {
    const totalWeight = endpoints.reduce((sum, e) => sum + e.weight, 0);
    let random = Math.random() * totalWeight;

    for (const endpoint of endpoints) {
        random -= endpoint.weight;
        if (random <= 0) return endpoint;
    }
    return endpoints[0];
}

// Main test function
export default function () {
    const endpoint = selectEndpoint();
    const url = `${BASE_URL}${endpoint.path}`;

    const params = {
        headers: {
            'Content-Type': 'application/json',
            'X-Request-ID': `k6-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        },
        timeout: '30s',
    };

    let response;
    const start = Date.now();

    if (endpoint.method === 'GET') {
        response = http.get(url, params);
    } else if (endpoint.method === 'POST') {
        const payload = JSON.stringify({
            timestamp: new Date().toISOString(),
            data: 'test payload',
        });
        response = http.post(url, payload, params);
    }

    const duration = Date.now() - start;
    latency.add(duration);

    // Check response
    const success = check(response, {
        'status is 2xx': (r) => r.status >= 200 && r.status < 300,
        'response time < 500ms': (r) => r.timings.duration < 500,
        'has response body': (r) => r.body && r.body.length > 0,
    });

    errorRate.add(!success);

    // Small sleep between requests
    sleep(Math.random() * 0.1);
}

// Setup function
export function setup() {
    console.log(`Testing Prism at ${BASE_URL}`);

    // Verify server is up
    const response = http.get(`${BASE_URL}/`);
    if (response.status !== 200 && response.status !== 404) {
        console.warn(`Server returned status ${response.status}`);
    }

    return { startTime: Date.now() };
}

// Teardown function
export function teardown(data) {
    const duration = (Date.now() - data.startTime) / 1000;
    console.log(`Test completed in ${duration.toFixed(2)} seconds`);
}

// Summary handler
export function handleSummary(data) {
    return {
        'stdout': textSummary(data, { indent: ' ', enableColors: true }),
        'load-test-results.json': JSON.stringify(data, null, 2),
    };
}

// Text summary (simplified)
function textSummary(data) {
    const metrics = data.metrics;
    return `
========================================
         PRISM LOAD TEST RESULTS
========================================

Requests:
  Total:    ${metrics.http_reqs?.values?.count || 0}
  Failed:   ${metrics.http_req_failed?.values?.rate?.toFixed(4) || 0}

Response Times:
  Avg:      ${metrics.http_req_duration?.values?.avg?.toFixed(2) || 0}ms
  Med:      ${metrics.http_req_duration?.values?.med?.toFixed(2) || 0}ms
  P95:      ${metrics.http_req_duration?.values?.['p(95)']?.toFixed(2) || 0}ms
  P99:      ${metrics.http_req_duration?.values?.['p(99)']?.toFixed(2) || 0}ms
  Max:      ${metrics.http_req_duration?.values?.max?.toFixed(2) || 0}ms

Throughput:
  Req/s:    ${(metrics.http_reqs?.values?.rate || 0).toFixed(2)}

========================================
`;
}
