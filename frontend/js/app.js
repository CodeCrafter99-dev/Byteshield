/**
 * ByteShield Frontend — Main Application Controller
 * Manages page state, navigation, and initialization
 */

const App = (() => {
  const authSection = () => document.getElementById('authSection');
  const scannerSection = () => document.getElementById('scannerSection');
  const navLinks = () => document.getElementById('navLinks');
  const authMessage = () => document.getElementById('authMessage');

  /**
   * Show a message in the auth section
   */
  function showAuthMessage(text, isError = false) {
    const el = authMessage();
    el.textContent = text;
    el.className = 'auth-message ' + (isError ? 'error' : 'success');
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 4000);
  }

  /**
   * Switch to authenticated state (show scanner)
   */
  function showApp() {
    authSection().classList.add('hidden');
    scannerSection().classList.remove('hidden');
    navLinks().classList.remove('hidden');
  }

  /**
   * Switch to unauthenticated state (show login)
   */
  function showAuth() {
    authSection().classList.remove('hidden');
    scannerSection().classList.add('hidden');
    navLinks().classList.add('hidden');
  }

  /**
   * Initialize the application
   */
  async function init() {
    // Setup auth form toggles
    document.getElementById('showSignup')?.addEventListener('click', (e) => {
      e.preventDefault();
      document.getElementById('loginForm').classList.add('hidden');
      document.getElementById('signupForm').classList.remove('hidden');
    });

    document.getElementById('showLogin')?.addEventListener('click', (e) => {
      e.preventDefault();
      document.getElementById('signupForm').classList.add('hidden');
      document.getElementById('loginForm').classList.remove('hidden');
    });

    // Login form submission
    document.getElementById('loginFormEl')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('loginUsername').value.trim();
      const password = document.getElementById('loginPassword').value;
      try {
        await Auth.login(username, password);
        showApp();
      } catch (err) {
        showAuthMessage(err.message, true);
      }
    });

    // Signup form submission
    document.getElementById('signupFormEl')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('signupUsername').value.trim();
      const email = document.getElementById('signupEmail').value.trim();
      const password = document.getElementById('signupPassword').value;
      try {
        await Auth.signup(username, email, password);
        showAuthMessage('Account created! Welcome to ByteShield.', false);
        showApp();
      } catch (err) {
        showAuthMessage(err.message, true);
      }
    });

    // Logout
    document.getElementById('navLogout')?.addEventListener('click', async () => {
      await Auth.logout();
      showAuth();
      // Clear form fields
      document.querySelectorAll('input').forEach(input => input.value = '');
      document.querySelectorAll('textarea').forEach(ta => ta.value = '');
    });

    // Initialize scanner components
    Scanner.initTabs();
    Scanner.initFileUploads();
    Scanner.initScanButtons();

    // Check existing session
    const isLoggedIn = await Auth.checkSession();
    if (isLoggedIn) {
      showApp();
    } else {
      showAuth();
    }
  }

  // Run on DOM ready
  document.addEventListener('DOMContentLoaded', init);

  return { showApp, showAuth };
})();
