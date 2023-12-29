function addText(field, num) {
    var inputText = ''

    if (field == 'iocs') {
        var e = document.getElementById("types")
        inputText1 = e.options[e.selectedIndex].text;

        inputText2 = document.getElementById(field).value;

        inputText = inputText1 + ": " + inputText2;
    } else if (field == 'subtechnique') {
        var e1 = document.getElementById("tactic")
        inputText1 = e1.options[e1.selectedIndex].text;

        var e2 = document.getElementById("technique")
        inputText2 = e2.options[e2.selectedIndex].text;

        var e3 = document.getElementById("subtechnique")
        inputText3 = e3.options[e3.selectedIndex].text;

        inputText = inputText1 + ' ' + inputText2 + '\n' + inputText3;
    } else {
        var e = document.getElementById(field)
        inputText = e.options[e.selectedIndex].text;
    }
    
    var list = document.getElementById('textList'+num);
    var entry = document.createElement('li');
    var deleteBtn = document.createElement('button');

    deleteBtn.textContent = 'Delete';
    deleteBtn.onclick = function() {
        list.removeChild(entry);
    };

    entry.appendChild(document.createTextNode(inputText));
    entry.appendChild(deleteBtn);
    list.appendChild(entry);
}

// document.getElementById('dataForm').addEventListener('submit', function(e) {
// e.preventDefault();
// // Process form data
// });

document.getElementById('dataForm').addEventListener('submit', function(e) {
    e.preventDefault();

    // Object to hold data from all lists
    var formData = {
        title: document.getElementById('title').value,
        author: document.getElementById('author').value,
        description: document.getElementById('description').value,
        groups: getListData('textList1'),
        subtechniques: getListData('textList2'),
        iocs: getListData('textList3')
    };

    // Send formData to server or process it as needed
    console.log(formData); // Replace with AJAX call or other processing
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open( "POST", "http://localhost:8000/submit", false ); // false for synchronous request
    xmlHttp.setRequestHeader('Content-type', 'application/json');
    xmlHttp.send(JSON.stringify(formData));
    window.open("http://localhost:8000/report")

});

function getListData(listId) {
var listItems = document.getElementById(listId).children;
var dataList = [];

for (var i = 0; i < listItems.length; i++) {
    dataList.push(listItems[i].textContent.replace('Delete', '').trim());
}

return dataList;
}