<#import "template.ftl" as layout>

<@layout.registrationLayout displayMessage=true; section>
  <#if section == "header">
    ${msg("loginOtpTitle")!"Enter OTP"}
  
  <#elseif section == "form">
    <form id="kc-otp-login-form" class="form" action="${url.loginAction}" method="post">
      <div class="form-group">
        <label for="otp">Enter OTP sent to your phone:</label>
        <input type="text" id="otp" name="otp" class="form-control" autofocus />
      </div>
      <div class="form-group">
        <input class="btn btn-primary" type="submit" value="Verify OTP"/>
      </div>
    </form>

    <form id="kc-otp-resend-form" class="form" action="${url.loginAction}" method="post" style="margin-top: 10px;">
      <input type="hidden" name="resendOtp" value="true"/>
      <div class="form-group">
        <input class="btn btn-secondary" type="submit" value="Resend OTP"/>
      </div>
    </form>
  </#if>
</@layout.registrationLayout>

