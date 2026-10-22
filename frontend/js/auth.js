/**
 * ByteShield Frontend — Authentication Module
 * Handles login, signup, logout, and session management
 */

const Auth = (() => {
  let currentUser = null;

  /**
   * Check if user is already logged in
   */
  async function checkSession() {
    try {
      const res = await fetch('/api/auth/me');
      if (res.ok) {
        const data = await res.json();
        currentUser = data.user;
        return true;
      }
      return false;
    } catch (err) {
      console.error('Session check failed:', err);
      return false;
    }
  }

  /**
   * Login user
   */
  async function login(username, password) {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Login failed.');
    }
    currentUser = data.user;
    return data;
  }

  /**
   * Signup user
   */
  async function signup(username, email, password) {
    const res = await fetch('/api/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password })
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Signup failed.');
    }
    currentUser = data.user;
    return data;
  }

  /**
   * Logout user
   */
  async function logout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch (err) {
      console.error('Logout error:', err);
    }
    currentUser = null;
  }

  /**
   * Get current user
   */
  function getUser() {
    return currentUser;
  }

  return { checkSession, login, signup, logout, getUser };
})();
