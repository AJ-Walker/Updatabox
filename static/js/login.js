
const email = document.getElementById('email');
const passwd = document.getElementById('pass');
// console.log(fullname, email, passwd, passwdC)
form = document.getElementById('loginForm');


const checkEmail = () => {
    const emailReq = document.getElementById('emailReq');
    let valid = false;
    const emailV = email.value.trim();
    if (!isRequired(emailV)) {
        showError('Email cannot be blank.', emailReq);
    } else if (!isEmailValid(emailV)) {
        showError('Email is not valid.', emailReq)
    } else {
        showSuccess(emailReq);
        valid = true;
    }
    return valid;
};

const checkPassword = () => {
    const passwdReg = document.getElementById('passReq');
    let valid = false;

    const password = passwd.value.trim();

    if (!isRequired(password)) {
        showError('Password cannot be blank.', passwdReg);
    } else if (!isPasswordSecure(password)) {
        showError('Password must has at least 8 characters that include at least 1 lowercase character, 1 uppercase characters, 1 number, and 1 special character in (!@#$%^&*)', passwdReg);
    } else {
        showSuccess(passwdReg);
        valid = true;
    }

    return valid;
};


const isEmailValid = (email) => {
    const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
};

const isPasswordSecure = (password) => {
    const re = new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})");
    return re.test(password);
};

const isRequired = value => value === '' ? false : true;

const showError = (message, whichEl) => {

    // add the error class
    whichEl.classList.remove('is-success');
    whichEl.classList.add('is-danger');

    // show the error message
    whichEl.innerHTML = message;
};

const showSuccess = (whichSc) => {
    
    // remove the error class
    whichSc.classList.remove('is-danger');
    whichSc.classList.add('is-success');

    // hide the error message
    whichSc.innerHTML = '';
}

form.addEventListener('submit', function (e) {
    // prevent the form from submitting
    e.preventDefault();
    
    // validate fields
    let isEmailValid = checkEmail(),
        isPasswordValid = checkPassword();

    let isFormValid = isEmailValid && isPasswordValid;

    // submit to the server if the form is valid
    if (isFormValid) {
        console.log('correct');
        form.submit();
        console.log('form submitted');

    }
});


const debounce = (fn, delay = 500) => {
    let timeoutId;
    return (...args) => {
        // cancel the previous timer
        if (timeoutId) {
            clearTimeout(timeoutId);
        }
        // setup a new timer
        timeoutId = setTimeout(() => {
            fn.apply(null, args)
        }, delay);
    };
};

form.addEventListener('input', debounce(function (e) {
    switch (e.target.id) {
        case 'email':
            checkEmail();
            break;
        case 'pass':
            checkPassword();
            break;
    }
}));