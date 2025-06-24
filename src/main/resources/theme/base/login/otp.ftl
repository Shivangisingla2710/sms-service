<form id="kc-otp-login-form" class="form" action="${url.loginAction}" method="post">
  <div class="form-group">
    <label for="otp">Enter OTP sent to your phone:</label>
    <input type="text" id="otp" name="otp" class="form-control" autofocus />
  </div>
  <div class="form-group">
    <input class="btn btn-primary" type="submit" value="Verify OTP"/>
  </div>
</form>
