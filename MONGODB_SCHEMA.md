# MongoDB Storage Schema

## Collection: `urlchecks`

### Schema Structure

```javascript
{
  // User identification
  userId: ObjectId,           // Reference to User collection
  user: ObjectId,             // Backward compatibility field
  
  // Scan type
  type: String,               // 'url' or 'message'
  
  // Input data
  url: String,                // URL being scanned (for type='url')
  text: String,               // Message content (for type='message') or URL
  
  // Analysis results
  prediction: String,         // 'phishing' or 'legitimate'
  confidence: Number,         // 0-100 percentage
  
  // Detailed analysis
  features: Object,           // Feature values used for prediction
  signals: Array<String>,     // List of suspicious signals detected
  
  // Timestamps
  checkedAt: Date,            // When the scan was performed
  date: Date,                 // Backward compatibility
  createdAt: Date,            // Auto-generated
  updatedAt: Date             // Auto-generated
}
```

---

## Example Documents

### URL Scan Example

```json
{
  "_id": "673ab12345678901234abcde",
  "userId": "673ab09876543210fedcba98",
  "user": "673ab09876543210fedcba98",
  "type": "url",
  "url": "https://github.com",
  "text": "https://github.com",
  "prediction": "legitimate",
  "confidence": 98.5,
  "features": {
    "having_IP_Address": -1,
    "having_Sub_Domain": -1,
    "SSLfinal_State": -1,
    "Domain_registeration_length": -1,
    "Request_URL": -1,
    "URL_of_Anchor": -1,
    "Links_in_tags": -1,
    "SFH": -1,
    "age_of_domain": -1,
    "DNSRecord": -1,
    "Prefix_Suffix": -1,
    "URL_Length": -1,
    "HTTPS_token": -1,
    "Redirect": -1
  },
  "signals": [],
  "checkedAt": "2025-11-03T18:30:00.000Z",
  "date": "2025-11-03T18:30:00.000Z",
  "createdAt": "2025-11-03T18:30:00.123Z",
  "updatedAt": "2025-11-03T18:30:00.123Z"
}
```

### Message/Email/SMS Scan Example

```json
{
  "_id": "673ab12345678901234abcdf",
  "userId": "673ab09876543210fedcba98",
  "user": "673ab09876543210fedcba98",
  "type": "message",
  "url": null,
  "text": "URGENT! Your bank account has been compromised! Click here immediately...",
  "prediction": "phishing",
  "confidence": 95.2,
  "features": {
    "num_urls": 1,
    "url_with_ip": -1,
    "has_shortened_url": -1,
    "urgency_score": 1,
    "financial_score": 1,
    "suspicious_score": -1,
    "threat_score": 1,
    "excessive_punctuation": 1,
    "all_caps_ratio": 1,
    "spelling_quality": 0,
    "sender_mismatch": 0,
    "has_phone_number": -1,
    "requests_personal_info": -1,
    "message_length": -1,
    "suspicious_domain": -1
  },
  "signals": [
    "Urgent language detected",
    "Financial keywords detected",
    "Threatening language detected",
    "Excessive punctuation",
    "Excessive capitalization"
  ],
  "checkedAt": "2025-11-03T18:35:00.000Z",
  "date": "2025-11-03T18:35:00.000Z",
  "createdAt": "2025-11-03T18:35:00.456Z",
  "updatedAt": "2025-11-03T18:35:00.456Z"
}
```

---

## Feature Values Explained

### URL Features (14 features)
All values normalized to: `-1` (safe), `0` (neutral), `1` (suspicious)

- `having_IP_Address`: URL uses IP instead of domain
- `having_Sub_Domain`: Multiple suspicious subdomains
- `SSLfinal_State`: SSL certificate validity
- `Domain_registeration_length`: Domain registration period
- `Request_URL`: External resources loaded
- `URL_of_Anchor`: Anchor tag analysis
- `Links_in_tags`: Links in meta/script tags
- `SFH`: Server Form Handler check
- `age_of_domain`: Domain age from WHOIS
- `DNSRecord`: DNS record existence
- `Prefix_Suffix`: "-" in domain name
- `URL_Length`: Unusually long URL
- `HTTPS_token`: "https" keyword in domain
- `Redirect`: Number of redirects

### Message Features (15 features)
All values normalized to: `-1` (safe), `0` (neutral), `1` (suspicious)

- `num_urls`: Number of URLs in text
- `url_with_ip`: URL contains IP address
- `has_shortened_url`: URL shortener detected
- `urgency_score`: Urgent/pressure language
- `financial_score`: Financial keywords
- `suspicious_score`: Prize/lottery keywords
- `threat_score`: Threatening language
- `excessive_punctuation`: Too many !!! or ???
- `all_caps_ratio`: Excessive capitalization
- `spelling_quality`: Misspellings detected
- `sender_mismatch`: Sender domain mismatch
- `has_phone_number`: Contains phone number
- `requests_personal_info`: Asks for sensitive data
- `message_length`: Unusual length
- `suspicious_domain`: Suspicious domain patterns

---

## Indexes

For performance optimization:

```javascript
// Compound index for user queries
{ userId: 1, checkedAt: -1 }

// Index for filtering by type
{ type: 1 }

// Index for filtering by prediction
{ prediction: 1 }
```

---

## Queries

### Get all scans for a user
```javascript
db.urlchecks.find({ userId: ObjectId("...") })
  .sort({ checkedAt: -1 })
```

### Get URL scans only
```javascript
db.urlchecks.find({ 
  userId: ObjectId("..."),
  type: "url" 
})
```

### Get message scans only
```javascript
db.urlchecks.find({ 
  userId: ObjectId("..."),
  type: "message" 
})
```

### Get phishing detections
```javascript
db.urlchecks.find({ 
  userId: ObjectId("..."),
  prediction: "phishing" 
})
```

### Get scans with specific signals
```javascript
db.urlchecks.find({ 
  signals: { $in: ["Urgent language detected"] }
})
```

---

## Storage Size Estimation

- **URL Scan**: ~500-800 bytes per document
- **Message Scan**: ~800-1500 bytes per document (depends on text length)
- **Features Object**: ~300-400 bytes
- **Signals Array**: ~100-500 bytes (varies by number of signals)

For 10,000 scans: ~5-15 MB storage
