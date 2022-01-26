var protocolInstance;

window.onload = () => {

    document.getElementById("myBtn").addEventListener('click', () => {

        document.getElementById("myBtn").parentNode.parentNode.parentNode.classList.remove('is-active');
        document.getElementById("myBtn2FA").parentNode.parentNode.parentNode.classList.add('is-active');


        var elements = document.getElementById("myForm").elements;

        var transactionID = window.location.href.split('/').pop();




        protocolInstance = protocol(elements.item(0).value, elements.item(1).value, transactionID)
    });

    document.getElementById("myBtn2FA").addEventListener('click', () => {
        /*document.querySelector('.tabs .tab.is-active').classList.remove('is-active');
        tab_switcher.parentNode.classList.add('is-active');
        
        SwitchPage(page_id);*/
        var elements = document.getElementById("myForm2FA").elements;

        protocolInstance.paymentInfo["2FAToken"] = elements.item(0).value
        protocolInstance.step()

    });

}


function updateInterface(status, message) {
    if (!status) {
        document.getElementById("myBtn").parentNode.parentNode.parentNode.classList.remove('is-active');
        document.getElementById("myBtn2FA").parentNode.parentNode.parentNode.classList.remove('is-active');
    }

    document.getElementById("messages").classList.remove('is-danger')
    document.getElementById("messages").classList.remove('is-success')
    if (status) {
        document.getElementById("messages").classList.add('is-success')
    } else {
        document.getElementById("messages").classList.add('is-danger')
    }

    document.getElementById("messages").innerHTML = message;
}

//window.location.replace("http://www.w3schools.com");

