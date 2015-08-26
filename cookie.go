package main

import (
	"crypto/rand"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dchest/captcha"
	"github.com/dgrijalva/jwt-go"
)

type CaptchaContext struct {
	Generator     http.Handler
	Epoch         time.Time
	Key           []byte
	ValidDuration time.Duration
}

func GenerateCaptchaKey() (result []byte) {
	result = make([]byte, 32)
	if _, err := rand.Read(result); err != nil {
		log.Fatal("Unable to generate Captcha Key.")
	}
	return
}

func (self *CaptchaContext) ValidToken(tknstr string) bool {
	token, err := jwt.Parse(tknstr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v.", token.Header["alg"])
		}
		return self.Key, nil
	})
	if err != nil {
		return false
	}
	if !token.Valid {
		return false
	}

	expstr, ok := token.Claims["exp"]
	if !ok {
		return false
	}

	var exp time.Time
	if exp, err = time.Parse("2006-01-02T15:04:05.999999999-07:00", expstr.(string)); err != nil {
		return false
	}

	if !time.Now().Before(exp) {
		return false
	}
	return true
}

func (self *CaptchaContext) GenerateToken() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["human"] = true
	token.Claims["exp"] = time.Now().Add(self.ValidDuration)
	return token.SignedString(self.Key)
}

func (self *CaptchaContext) Challenge(w http.ResponseWriter, r *http.Request, edge string) *ProxyError {
	captchaId := r.PostFormValue("captchaId")
	solution := r.PostFormValue("captchaSolution")

	// Verify the input.
	if captcha.VerifyString(captchaId, solution) {
		token, err := self.GenerateToken()
		if err != nil {
			return &ProxyError{
				Code: 500,
				Msg:  "Unable to generate token value.",
				Err:  err,
			}
		}
		// Strip the port off, since I cannot use them in the cookie.
		parts := strings.Split(edge, ":")
		http.SetCookie(w, &http.Cookie{
			Name:    HumanCookieName,
			Value:   token,
			Expires: time.Now().Add(self.ValidDuration),
			Domain:  "." + parts[0],
			Path:    "/",
		})
		http.Redirect(w, r, r.URL.Path, 302)
		return nil
	}

	// Deal with displaying the Captcha.
	if strings.HasPrefix(r.URL.Path, "/captcha/") {
		self.Generator.ServeHTTP(w, r)
		return nil
	} else {
		if err := captchaTemplate.Execute(w, &struct{ CaptchaId string }{captcha.New()}); err != nil {
			return &ProxyError{
				Code: 500,
				Msg:  "Unable to generate captcha page.",
				Err:  err,
			}
		}
		return nil
	}
}

var captchaTemplate = template.Must(template.New("captcha").Parse(`
<!doctype html>
<head><title>Robot-free zone</title></head>
<body>
<script>
function setSrcQuery(e, q) {
        var src  = e.src;
        var p = src.indexOf('?');
        if (p >= 0) {
                src = src.substr(0, p);
        }
        e.src = src + "?" + q
}

function playAudio() {
        var lang = 'en';
        var e = document.getElementById('audio');
        setSrcQuery(e, "lang=" + lang);
        e.style.display = 'block';
        e.autoplay = 'true';
        return false;
}

function reload() {
        setSrcQuery(document.getElementById('image'), "reload=" + (new Date()).getTime());
        setSrcQuery(document.getElementById('audio'), (new Date()).getTime());
        return false;
}
</script>
<h1>Are you human?</h1>
<p>This services is for humans only. Please verify you are not a bot by entering the numbers below:</p>
<form action="." method="POST">
<p><img id=image src="/captcha/{{.CaptchaId}}.png" alt="Captcha image"></p>
<a href="#" onclick="reload()">Reload</a> | <a href="#" onclick="playAudio()">Play Audio</a>
<audio id=audio controls style="display:none" src="/captcha/{{.CaptchaId}}.wav" preload=none>
  You browser doesn't support audio.
  <a href="/captcha/{{.CaptchaId}}.wav">Download file</a> to play it in the external player.
</audio>
<input type="hidden" name="captchaId" value="{{.CaptchaId}}"><br>
<input type="text" name="captchaSolution">
<input type="submit" value="Submit">
</form>
<br/><br/>
`))
