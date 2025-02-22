// Simulating user login status
let isLoggedIn = false; // Initial state: user is not logged in

// Get the login button
const loginButton = document.getElementById('loginButton');

// Update the button text based on login status
function updateLoginButton() {
  if (isLoggedIn) {
    loginButton.textContent = 'Log out';
    loginButton.classList.remove('btn-outline-dark');
    loginButton.classList.add('btn-danger'); // Optional styling change for log out
  } else {
    loginButton.textContent = 'Login';
    loginButton.classList.remove('btn-danger');
    loginButton.classList.add('btn-outline-dark'); // Optional styling change for login
  }
}

// Add click event listener to the login button
loginButton.addEventListener('click', () => {
  if (isLoggedIn) {
    // Simulate logging out
    isLoggedIn = false;
    alert('You have logged out.');
  } else {
    // Simulate logging in
    isLoggedIn = true;
    alert('You are now logged in.');
  }
  // Update button text based on new login status
  updateLoginButton();
});

// Initialize the button text on page load
updateLoginButton();
