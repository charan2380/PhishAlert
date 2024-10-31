function submitForm() {
    document.getElementById("captchaForm").submit();
}

function captchaCallback() {
    submitForm();
}

function resetInput() {
    document.getElementById("basic-url").value = "";
}

function showLoadingSpinner() {
    document.getElementById("loadingSpinner").style.display = "block";
    document.getElementById("urlForm").style.display = "none";
}
