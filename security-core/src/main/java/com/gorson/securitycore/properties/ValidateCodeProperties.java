package com.gorson.securitycore.properties;

public class ValidateCodeProperties {
	
	private ImageCodeProperties image = new ImageCodeProperties(); //图形验证码
	
	private SmsCodeProperties sms = new SmsCodeProperties(); //短信验证码

	public ImageCodeProperties getImage() {
		return image; 
	}

	public void setImage(ImageCodeProperties image) {
		this.image = image;
	}

	public SmsCodeProperties getSms() {
		return sms;
	}

	public void setSms(SmsCodeProperties sms) {
		this.sms = sms;
	}
	
}
