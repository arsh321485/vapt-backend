(function () {
  function secondsToText(seconds) {
    var sec = Math.max(0, Math.round(seconds || 0));
    var mins = Math.floor(sec / 60);
    var rem = sec % 60;
    if (mins > 0) return mins + " min " + rem + " sec";
    return rem + " sec";
  }

  function estimateUploadSeconds(file) {
    if (!file) return 0;
    var sizeMb = (file.size || 0) / (1024 * 1024);
    var ext = "";
    var dot = file.name.lastIndexOf(".");
    if (dot >= 0) ext = file.name.slice(dot).toLowerCase();

    var estimate;
    if (ext === ".nessus" || ext === ".xml" || ext === ".html" || ext === ".htm") {
      estimate = 20 + sizeMb * 4.0;
    } else if (ext === ".xlsx" || ext === ".xls" || ext === ".csv") {
      estimate = 8 + sizeMb * 1.5;
    } else {
      estimate = 6 + sizeMb * 1.0;
    }
    if (estimate < 8) estimate = 8;
    if (estimate > 3600) estimate = 3600;
    return Math.round(estimate);
  }

  function ensureInfoBox(formEl) {
    var existing = document.getElementById("upload-time-estimate-box");
    if (existing) return existing;

    var box = document.createElement("div");
    box.id = "upload-time-estimate-box";
    box.style.margin = "10px 0";
    box.style.padding = "10px 12px";
    box.style.border = "1px solid #c7d7e2";
    box.style.background = "#f3f8fc";
    box.style.color = "#1f3b4d";
    box.style.borderRadius = "4px";
    box.style.fontSize = "13px";
    box.style.lineHeight = "1.5";
    box.style.display = "none";

    var submitRow = formEl.querySelector(".submit-row");
    if (submitRow && submitRow.parentNode) {
      submitRow.parentNode.insertBefore(box, submitRow);
    } else {
      formEl.appendChild(box);
    }
    return box;
  }

  function renderLastUploadSummaryCard() {
    var messageList = document.querySelector(".messagelist");
    if (!messageList) return;

    var successItems = Array.prototype.slice.call(
      messageList.querySelectorAll(".success")
    );
    var infoItems = Array.prototype.slice.call(
      messageList.querySelectorAll(".info")
    );
    if (!successItems.length && !infoItems.length) return;

    var successText = successItems.map(function (el) {
      return (el.textContent || "").trim();
    }).join(" ");
    var infoText = infoItems.map(function (el) {
      return (el.textContent || "").trim();
    }).join(" ");

    if (
      successText.indexOf("Upload processing time:") === -1 &&
      infoText.indexOf("Estimated total (upload + agent):") === -1
    ) {
      return;
    }

    function extractByLabel(text, label) {
      var idx = text.indexOf(label);
      if (idx < 0) return "";
      var tail = text.slice(idx + label.length).trim();
      var stop = tail.indexOf(".");
      if (stop >= 0) tail = tail.slice(0, stop).trim();
      return tail;
    }

    var actualUpload = extractByLabel(successText, "Upload processing time:");
    var estimatedUpload = extractByLabel(successText, "Estimated upload time:");
    var estimatedAgent = extractByLabel(infoText, "Estimated agent creation time:");
    var estimatedTotal = extractByLabel(infoText, "Estimated total (upload + agent):");

    var card = document.createElement("div");
    card.id = "last-upload-summary-card";
    card.style.margin = "10px 0 14px 0";
    card.style.padding = "12px 14px";
    card.style.border = "1px solid #bfd8c2";
    card.style.borderRadius = "4px";
    card.style.background = "#edf8ee";
    card.style.color = "#1f3b1f";
    card.style.fontSize = "13px";
    card.style.lineHeight = "1.6";
    card.innerHTML =
      "<strong>Last Upload Time Summary</strong><br>" +
      "<span><strong>Actual upload:</strong> " + (actualUpload || "-") + "</span>&nbsp;&nbsp;|&nbsp;&nbsp;" +
      "<span><strong>Estimated upload:</strong> " + (estimatedUpload || "-") + "</span><br>" +
      "<span><strong>Estimated agent creation:</strong> " + (estimatedAgent || "-") + "</span>&nbsp;&nbsp;|&nbsp;&nbsp;" +
      "<span><strong>Estimated total:</strong> " + (estimatedTotal || "-") + "</span>";

    messageList.parentNode.insertBefore(card, messageList.nextSibling);
  }

  function bindAdminUploadTiming() {
    var form = document.querySelector("form");
    var fileInput = document.getElementById("id_file");
    renderLastUploadSummaryCard();
    if (!form || !fileInput) return;

    var infoBox = ensureInfoBox(form);
    var startedAt = 0;
    var timer = null;

    function updateEstimate() {
      var file = fileInput.files && fileInput.files[0];
      if (!file) {
        infoBox.style.display = "none";
        return;
      }

      var etaSeconds = estimateUploadSeconds(file);
      var sizeMb = ((file.size || 0) / (1024 * 1024)).toFixed(2);

      infoBox.innerHTML =
        "<strong>Estimated upload processing time:</strong> " + secondsToText(etaSeconds) +
        " &nbsp;|&nbsp; <strong>File:</strong> " + file.name +
        " (" + sizeMb + " MB)" +
        "<br><small>After upload, agent/card creation starts in background and total time can be higher.</small>";
      infoBox.style.display = "block";
    }

    fileInput.addEventListener("change", updateEstimate);
    updateEstimate();

    form.addEventListener("submit", function () {
      var file = fileInput.files && fileInput.files[0];
      if (!file) return;

      startedAt = Date.now();
      var etaSeconds = estimateUploadSeconds(file);

      if (timer) {
        clearInterval(timer);
        timer = null;
      }

      infoBox.style.display = "block";
      timer = setInterval(function () {
        var elapsed = Math.floor((Date.now() - startedAt) / 1000);
        var remaining = Math.max(0, etaSeconds - elapsed);
        infoBox.innerHTML =
          "<strong>Uploading and processing...</strong>" +
          " &nbsp;|&nbsp; <strong>Elapsed:</strong> " + secondsToText(elapsed) +
          " &nbsp;|&nbsp; <strong>ETA:</strong> " + secondsToText(etaSeconds) +
          " &nbsp;|&nbsp; <strong>Remaining:</strong> " + secondsToText(remaining) +
          "<br><small>Please wait, this can take longer for large reports.</small>";
      }, 1000);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindAdminUploadTiming);
  } else {
    bindAdminUploadTiming();
  }
})();
