CREATE DATABASE IF NOT EXISTS absega_det;
USE absega_det;

CREATE TABLE mitre_techniques (
    id VARCHAR(20) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    tactic VARCHAR(100) NOT NULL,
    description TEXT,
    platform VARCHAR(255),
    url VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE telemetry_sources (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    platform VARCHAR(100),
    description TEXT,
    status ENUM('healthy','degraded','missing') DEFAULT 'healthy',
    event_rate VARCHAR(100),
    coverage TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE detections (
    id VARCHAR(20) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity ENUM('critical','high','medium','low') NOT NULL,
    status ENUM('draft','testing','active','disabled') DEFAULT 'draft',
    category ENUM('windows','linux','identity') DEFAULT 'windows',
    author VARCHAR(100),
    false_positives TEXT,
    rule_path VARCHAR(500),
    sigma_rule TEXT,
    tags VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE validation_cases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    detection_id VARCHAR(20) NOT NULL,
    test_name VARCHAR(255) NOT NULL,
    test_type ENUM('TP','FP','TN','FN') NOT NULL,
    sample_event TEXT,
    expected_result ENUM('match','no_match') NOT NULL,
    actual_result ENUM('match','no_match'),
    passed BOOLEAN,
    notes TEXT,
    run_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (detection_id) REFERENCES detections(id)
);

CREATE TABLE detection_technique_mapping (
    id INT AUTO_INCREMENT PRIMARY KEY,
    detection_id VARCHAR(20) NOT NULL,
    technique_id VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (detection_id) REFERENCES detections(id),
    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id)
);

CREATE TABLE detection_telemetry (
    id INT AUTO_INCREMENT PRIMARY KEY,
    detection_id VARCHAR(20) NOT NULL,
    telemetry_id INT NOT NULL,
    required BOOLEAN DEFAULT TRUE,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (detection_id) REFERENCES detections(id),
    FOREIGN KEY (telemetry_id) REFERENCES telemetry_sources(id)
);
