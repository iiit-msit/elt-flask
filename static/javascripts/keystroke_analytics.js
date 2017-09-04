/*
 *  Track the Printable Events of a textarea
 */

var KeystrokeAnalaytics = {
  init: function(logs){
    this.textarea = document.getElementById("essayinput");
    this.logs = JSON.parse(logs);
    this.lastUpdate = Date.now()
    this.getPrinatableEvents();
  },

  getPrinatableEvents: function(){
    inp = this.textarea;
    logs = this.logs;
    this.currentText = "";
    currentText = this.currentText;
    lastUpdate = this.lastUpdate;
    /*
    **  IE6+ fires an event whenever there is a change in DOM element property.
    **  Handle :onpropertychange: event to trigger our function only if the property is "value"
    */

    /*
    **  Note that the triggered function has to be proxied before :attachEvent:.
    **  It is to retain scope of :this: by passing our input DOM to :attachEvent:
    */

    if ("onpropertychange" in inp)
        inp.attachEvent($.proxy(function () {
            if (event.propertyName == "value")
                logs[Date.now()] = {"text":this.value}
                currentText = this.value;
        }, inp));

    /*
    **  Listen to printable events of input field. Happy debugging
    */

    else
    inp.addEventListener("input", function (e) {
      newText = this.value;
      var newTextIndex = 0;
      var currentTextIndex = 0;
      var result = "";
      var addedWord = "";
      var status = "OK";
      var startIndex = 0;
      var endIndex = 0;
      if (newText.length < currentText.length){
        while (currentTextIndex < currentText.length){
            if ( currentText[currentTextIndex] != newText[newTextIndex]) {
              result+=currentText[currentTextIndex];
              addedWord += newText[newTextIndex];
            }
            else{
              newTextIndex++;
            }
            currentTextIndex++;
        }
        key = result;
        operation = "removed"
      }
      else{
        key = newText.replace(currentText,'');
        if (key.length > 1 && (newText.match(new RegExp(key, "g")) || []).length > 1)
          status = "copied"
        operation = "added"
      }

      timestamp = Date.now();

      if (lastUpdate == 0)
        timetaken = 0
      else
        timetaken = Math.abs(timestamp - lastUpdate)/1000

      // logs[timestamp] = {"previoustext":currentText, "text":newText, "status":status, "chars": key.length, "operation":operation, "timetaken":timetaken.toString()+" s"}
      logs[timestamp] = {"previoustext":currentText, "currenttext":newText, "timetaken":timetaken.toString()+" s"}
      currentText = this.value;
      lastUpdate = timestamp;
    }, false);
    /*
    **  Now that you understood :input: is not right one, good time detecting key combos!
    */
  },
  render: function(){
    const ordered = {};
    Object.keys(this.logs).sort().forEach(function(key) {
      ordered[key] = this.logs[key];
    });

    return this.logs;
  }
}
