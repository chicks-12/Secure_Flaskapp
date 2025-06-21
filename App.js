document.addEventListener('DOMContentLoaded', function() {
// Password visibility toggle
document.querySelectorAll('.toggle-password').forEach(button => {
button.addEventListener('click', function() {
const passwordField = this.closest('.input-group').querySelector('input');
const icon = this.querySelector('i');
if (passwordField.type === 'password') {
passwordField.type = 'text';
icon.classList.remove('bi-eye-fill');
icon.classList.add('bi-eye-slash-fill');
} else {
passwordField.type = 'password';
icon.classList.remove('bi-eye-slash-fill');
icon.classList.add('bi-eye-fill');
}
});
});

// Form validation enhancements
document.querySelectorAll('form').forEach(form => {
form.addEventListener('submit', function(e) {
const submitButton = this.querySelector('button[type="submit"]');
if (submitButton) {
submitButton.disabled = true;
submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';
}
});
});

// Auto-hide alerts after 5 seconds
setTimeout(() => {
document.querySelectorAll('.alert').forEach(alert => {
const bsAlert = new bootstrap.Alert(alert);
bsAlert.close();
});
}, 5000);
});
