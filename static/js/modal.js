// Wait for the DOM to load
document.addEventListener('DOMContentLoaded', function () {
    // Get modal elements
    const modal = document.querySelector('.modal');
    const newPasswordButton = document.querySelector('.new-password-button'); // Assuming this is the "New Password" button
    const closeButton = document.querySelector('.modal .close-button');

    // Show modal when the button is clicked
    newPasswordButton.addEventListener('DOMContentLoaded','click', function () {
        modal.style.display = 'block';
    });

    // Close modal when the close button is clicked
    closeButton.addEventListener('click', function () {
        modal.style.display = 'none';
    });

    // Close modal when clicking outside the modal
    window.addEventListener('click', function (event) {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
        });
        });
        document.querySelectorAll('.toggle-password').forEach(button => {
            button.addEventListener('click', function () {
                let input = this.previousElementSibling; // Get the password input field
                let icon = this.querySelector('i'); // Get the icon inside the button
                
                if (input.type === "password") {
                    input.type = "text";  // Show password
                    icon.classList.replace("bi-eye", "bi-eye-slash"); // Change icon
                } else {
                    input.type = "password";  // Hide password
                    icon.classList.replace("bi-eye-slash", "bi-eye"); // Change icon
                }
            });
        });