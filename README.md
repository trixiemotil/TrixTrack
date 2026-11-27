# Trix Track

Trix Track serves its web interface and API from one Node.js process. User accounts, transactions, wallets, categories, and goals are stored in MongoDB. Passwords are stored as salted scrypt hashes.

## Run locally

1. Install Node.js 18 or newer and have a MongoDB database available (MongoDB Atlas works).
2. Copy `.env.example` to `.env` and set `MONGODB_URI` to your MongoDB connection string. URL-encode special characters in the connection string password.
3. Install dependencies and start the app:

   ```sh
   npm install
   npm start
   ```

4. Open `http://localhost:3000`. Do not open `index.html` directly or use a static-only preview server; those do not provide the API.

By default, the app keeps a temporary sign-in token in browser session storage. If **Remember me** is selected at sign-in, the token and username are saved in local storage so the session can be restored after restarting the browser. All financial data is read from and written to MongoDB through authenticated API calls. Each account's data is isolated by its server-side user ID.
