var protocolInstance;

window.onload = () => {

    document.getElementById("myBtn").addEventListener('click', () => {

        document.getElementById("myBtn").parentNode.parentNode.parentNode.classList.remove('is-active');
        document.getElementById("myBtn2FA").parentNode.parentNode.parentNode.classList.add('is-active');

        
        var elements = document.getElementById("myForm").elements;

        var currentUrl = window.location.href;

        //let params = (new URL(url)).searchParams;
        //console.log(params.get('name'))


        protocolInstance = protocol(elements.item(0).value, elements.item(1).value, "<transactionid>")
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



function myFunction() {
    var elements = document.getElementById("myForm").elements;
    var obj = {};
    for (var i = 0; i < elements.length; i++) {
        var item = elements.item(i);
        obj[item.name] = item.value;
    }

    document.getElementById("demo").innerHTML = JSON.stringify(obj);
}