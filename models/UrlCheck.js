const mongoose = require("mongoose");

const UrlCheckSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, // Keeping for backward compatibility
  
  // Type of scan: 'url' or 'message'
  type: { type: String, enum: ['url', 'message'], default: 'url' },
  
  // URL field (for URL scans)
  url: { type: String, required: false },
  
  // Text field (for message/email/SMS scans)
  text: { type: String, required: false },
  
  // Prediction result
  prediction: { type: String, required: true, enum: ['phishing', 'legitimate'] },
  
  // Confidence score (0-100)
  confidence: { type: Number, required: true },
  
  // Additional metadata (features, signals, etc.)
  features: { type: Object, required: false },
  signals: { type: [String], required: false },
  
  // Timestamps
  checkedAt: { type: Date, default: Date.now },
  date: { type: Date, default: Date.now } // Keeping for backward compatibility
}, {
  timestamps: true // Adds createdAt and updatedAt automatically
});

// Index for faster queries
UrlCheckSchema.index({ userId: 1, checkedAt: -1 });
UrlCheckSchema.index({ type: 1 });
UrlCheckSchema.index({ prediction: 1 });

module.exports = mongoose.models.UrlCheck || mongoose.model("UrlCheck", UrlCheckSchema);