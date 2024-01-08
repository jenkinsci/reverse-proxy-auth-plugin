package org.jenkinsci.plugins.reverse_proxy_auth.data;

import java.io.IOException;

import hudson.model.User;
import hudson.tasks.Mailer;

/** 
 * User data forwarded by the reverse proxy
 * **/
public class ForwardedUserData {
	/** Empty header may be a null string **/
	private static final String NULL_HEADER="(null)";

	private String email;
	private String displayName;
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getDisplayName() {
		return displayName;
	}
	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}

	/** 
	 * Update the forwarded data to the jenkins user.
	 * @return true if updated and saved
	 * **/
	public boolean update(User user) {
		boolean toReturn = false;
		if(updateDisplayName(user) || updateEmail(user)){
			toReturn = true;
			try {
				user.save();
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}
		}

		return toReturn;
	}

	private boolean updateDisplayName(User user) {
		boolean toReturn = false;
		if(isNotNullHeader(displayName) && !displayName.equals(user.getFullName())){
			user.setFullName(displayName);
			toReturn = true;
		}
		return toReturn;
	}

	private boolean updateEmail(User user){
		boolean toReturn = false;
		if(isNotNullHeader(email)){
			Mailer.UserProperty emailProp = user.getProperty(Mailer.UserProperty.class);
			if (emailProp == null || !email.equals(emailProp.getConfiguredAddress())) { 
				emailProp = new Mailer.UserProperty(email);
				try {
					user.addProperty(emailProp);
				} catch (IOException e) {
					throw new IllegalStateException(e);
				}
				toReturn=true;
			}
		}
		return toReturn;
	}

	private static boolean isNotNullHeader(String value){
		return value != null && !value.equals(NULL_HEADER);
	}

}