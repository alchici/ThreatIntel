    function getGroups() {
        var xmlHttp = new XMLHttpRequest();
        xmlHttp.open( "GET", "http://localhost:8000/groups", false ); // false for synchronous request
        xmlHttp.send( null );
        groups = JSON.parse(xmlHttp.responseText);

        for (group of groups) {
            var option = document.createElement("option");
            option.text = group["name"];
            option.value = group["name"];
            var select = document.getElementById("group")
            select.appendChild(option);      
        }
    }    
    
    function getTactics(){
        var xmlHttp = new XMLHttpRequest();
        xmlHttp.open( "GET", "http://localhost:8000/tactics", false ); // false for synchronous request
        xmlHttp.send( null );
        tactics = JSON.parse(xmlHttp.responseText);

        for (tactic of tactics) {
            var option = document.createElement("option");
            option.text = tactic["external_references"][0]["external_id"]+' '+tactic["name"];
            option.value = tactic["name"].toLowerCase().replace(/ /g, '-');
            var select = document.getElementById("tactic")
            select.appendChild(option);      
        }
    }

    function getTechniques(){
        var e = document.getElementById("tactic")
            inputText = e.value;

            var xmlHttp = new XMLHttpRequest();
            xmlHttp.open( "GET", "http://localhost:8000/techniques/"+inputText, false ); // false for synchronous request
            xmlHttp.send( null );
            techniques = JSON.parse(xmlHttp.responseText);

            var select = document.getElementById("technique")
            select.innerHTML = '';

            for (technique of techniques) {
                var option = document.createElement("option");
                option.text = technique["external_references"][0]["external_id"]+' '+technique["name"];
                option.value = technique["external_references"][0]["external_id"];
                select.appendChild(option);      
            }
    }

    function getSubtechniques() {
        var e1 = document.getElementById("tactic")
            inputText1 = e1.value;

            var e2 = document.getElementById("technique")
            inputText2 = e2.value;

            var xmlHttp = new XMLHttpRequest();
            xmlHttp.open( "GET", "http://localhost:8000/subtechniques/"+inputText1+'/'+inputText2, false ); // false for synchronous request
            xmlHttp.send( null );
            subtechniques = JSON.parse(xmlHttp.responseText);

            var select = document.getElementById("subtechnique")
            select.innerHTML = '';

            if (subtechniques == '') {
                var option = document.createElement("option");
                option.text = "No sub-techniques";
                option.value = "empty";
                select.appendChild(option); 
            } else {
                for (subtechnique of subtechniques) {
                    var option = document.createElement("option");
                    option.text = subtechnique["external_references"][0]["external_id"]+' '+subtechnique["name"];
                    option.value = subtechnique["external_references"][0]["external_id"];
                    select.appendChild(option);      
                }
            }
    }
        
        

        document.getElementById("tactic").addEventListener('change',getTechniques);
        document.getElementById("tactic").addEventListener('change',getSubtechniques)
        document.getElementById("technique").addEventListener('change',getSubtechniques);

        getGroups()
        getTactics()
        getTechniques()
        getSubtechniques()