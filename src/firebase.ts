import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";

// Firebase web configuration is public client configuration, not a service-account secret.
const config = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || "AIzaSyCCi8AZP6SNexwP8_phr-8jqU7qxisB5DQ",
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || "mutah-hash.firebaseapp.com",
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || "mutah-hash",
  appId: import.meta.env.VITE_FIREBASE_APP_ID || "1:191209165350:web:b77e7a275f08eeeb26cce7"
};

export const auth = getAuth(initializeApp(config));
