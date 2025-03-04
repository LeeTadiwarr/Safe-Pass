function toggleCardNumber(icon) {
    const cardNumberContainer = icon.parentElement.querySelector('.d-flex.flex-column');
    const maskedCards = cardNumberContainer.querySelectorAll('.masked-card');
    const fullCards = cardNumberContainer.querySelectorAll('.full-card');

    maskedCards.forEach((maskedCard) => maskedCard.classList.toggle('d-none'));
    fullCards.forEach((fullCard) => fullCard.classList.toggle('d-none'));
    
    // Change icon based on visibility
    icon.classList.toggle('fa-eye');
    icon.classList.toggle('fa-eye-slash');
}

function toggleCvv(icon) {
    const cvvContainer = icon.parentElement;
    const maskedCvv = cvvContainer.querySelector('.masked-cvv');
    const fullCvv = cvvContainer.querySelector('.full-cvv');

    maskedCvv.classList.toggle('d-none');
    fullCvv.classList.toggle('d-none');
    
    // Change icon based on visibility
    icon.classList.toggle('fa-eye');
    icon.classList.toggle('fa-eye-slash');
}