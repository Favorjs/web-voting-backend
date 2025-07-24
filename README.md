# WhatsApp Voting System

## Environment Variables

Create a `.env` file in the server directory with the following variables:

```
# Database Configuration
DB_NAME=e-voting
DB_USER=root
DB_PASS=your_password
DB_HOST=localhost

# Twilio Configuration
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_WHATSAPP_NUMBER=your_twilio_whatsapp_number

# Server Configuration
PORT=3000
```

## Installation

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file with your configuration

3. Run the server:
```bash
npm start
```
