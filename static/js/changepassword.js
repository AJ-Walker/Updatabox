const passwd = document.getElementById('pass');
const passwdC = document.getElementById('passConf');
form = document.getElementById('signupForm');


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

const checkConfirmPassword = () => {
    const passwdCReg = document.getElementById('passCReq');
    let valid = false;
    // check confirm password
    const confirmPassword = passwdC.value.trim();
    const password = passwd.value.trim();

    if (!isRequired(confirmPassword)) {
        showError('Please enter the password again', passwdCReg);
    } else if (password !== confirmPassword) {
        showError('The password does not match', passwdCReg);
    } else {
        showSuccess(passwdCReg);
        valid = true;
    }

    return valid;
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
    // let openM = false;
    
    e.preventDefault();
    
    // validate fields
    let isPasswordValid = checkPassword(),
        isConfirmPasswordValid = checkConfirmPassword();

    let isFormValid = isPasswordValid && isConfirmPasswordValid;

    // submit to the server if the form is valid
    if (isFormValid) {
        console.log('correct');
        form.submit();
        console.log('form submitted');
        // mdl.classList.add('is-active');
        // console.log('modal activated');

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
        case 'pass':
            checkPassword();
            break;
        case 'passConf':
            checkConfirmPassword();
            break;
    }
}));





