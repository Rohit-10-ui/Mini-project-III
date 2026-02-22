# Render Deployment Guide

## Overview
This guide explains how to deploy the PhishGuard application to Render.com with MongoDB Atlas.

## Prerequisites
- GitHub repository with your code
- Render.com account
- MongoDB Atlas account

## Step 1: Setup MongoDB Atlas

1. Go to [MongoDB Atlas](https://cloud.mongodb.com)
2. Create a new cluster (free tier available)
3. Create a database user:
   - Database Access → Add New Database User
   - Username & Password authentication
   - Save credentials securely
4. Whitelist IP addresses:
   - Network Access → Add IP Address
   - Click "Allow Access from Anywhere" (0.0.0.0/0)
5. Get connection string:
   - Click "Connect" → "Connect your application"
   - Copy connection string
   - Replace `<password>` with your database user password

## Step 2: Deploy Flask Services on Render

### Flask URL Detection Service

1. Create New Web Service on Render
2. Connect your GitHub repository
3. Configure:
   - **Name**: `phishguard-flask-url`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python app.py`
   - **Instance Type**: Free
4. Add Environment Variables:
   - `PORT`: `7000`
   - `FLASK_ENV`: `production`
5. Deploy and copy the service URL (e.g., `https://phishguard-flask-url.onrender.com`)

### Flask Text Detection Service

1. Create another New Web Service
2. Connect your GitHub repository
3. Configure:
   - **Name**: `phishguard-flask-text`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python app_text.py`
   - **Instance Type**: Free
4. Add Environment Variables:
   - `PORT`: `5002`
   - `FLASK_ENV`: `production`
5. Deploy and copy the service URL (e.g., `https://phishguard-flask-text.onrender.com`)

## Step 3: Deploy Node.js Application

1. Create New Web Service on Render
2. Connect your GitHub repository
3. Configure:
   - **Name**: `phishguard-app`
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `node server.js`
   - **Instance Type**: Free

4. Add Environment Variables in Render Dashboard:

```
NODE_ENV=production
MONGODB_URI=<YOUR URI>
SESSION_SECRET=generate-a-random-32-char-string-here
GOOGLE_CLIENT_ID=your-google-oauth-client-id
GOOGLE_CLIENT_SECRET=your-google-oauth-client-secret
GOOGLE_CALLBACK_URL=https://phishguard-app.onrender.com/auth/google/callback
FLASK_URL=https://phishguard-flask-url.onrender.com
FLASK_SERVICE_URL=https://phishguard-flask-url.onrender.com
FLASK_TEXT_URL=https://phishguard-flask-text.onrender.com
FLASK_TEXT_SERVICE_URL=https://phishguard-flask-text.onrender.com
```

## Step 4: Setup Google OAuth (Optional)

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials:
   - Credentials → Create Credentials → OAuth 2.0 Client ID
   - Application type: Web application
   - Authorized redirect URIs: `https://your-app.onrender.com/auth/google/callback`
5. Copy Client ID and Client Secret to Render environment variables

## Step 5: Deploy

1. Click "Create Web Service" in Render
2. Wait for deployment to complete (5-10 minutes)
3. Check logs for any errors
4. Visit your app URL: `https://phishguard-app.onrender.com`

## Important Notes

### Free Tier Limitations
- Services spin down after 15 minutes of inactivity
- First request after spin down may take 30-60 seconds
- Consider upgrading to paid tier for production use

### Troubleshooting

**MongoDB connection fails:**
- Verify connection string is correct
- Check IP whitelist in MongoDB Atlas
- Ensure database user credentials are correct

**Flask services not responding:**
- Check if services are running in Render dashboard
- Verify environment variables are set
- Check service logs for errors

**Google OAuth fails:**
- Verify callback URL matches exactly
- Check client ID and secret are correct
- Ensure Google+ API is enabled

### Environment Variable Checklist
- [ ] MONGODB_URI set with correct password
- [ ] SESSION_SECRET is random and secure (32+ chars)
- [ ] FLASK_URL points to deployed Flask service
- [ ] FLASK_TEXT_URL points to deployed Flask Text service
- [ ] GOOGLE_CALLBACK_URL uses your Render domain
- [ ] NODE_ENV=production

## Monitoring

Monitor your services in Render Dashboard:
- Check logs for errors
- Monitor resource usage
- Set up alerts for downtime

## Switching Back to Localhost

To switch back to localhost development:
1. Uncomment localhost configuration in `server.js`
2. Comment out Render configuration
3. Use `.env.example` as reference for local environment variables
4. Run `mongod` locally
5. Start Flask services: `python app.py` and `python app_text.py`
6. Start Node server: `node server.js`
