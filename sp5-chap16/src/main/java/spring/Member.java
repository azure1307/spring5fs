package spring;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonFormat.Shape;
import com.fasterxml.jackson.annotation.JsonIgnore;

public class Member {
	
	private Long id;
	private String email;
	@JsonIgnore
	private String password;
	private String name;
//	@JsonFormat(pattern = "yyyyMMddHHmmss") // 패턴 속성 사용
//	@JsonFormat(shape = Shape.STRING) // ISO-8601 형식으로 변환
	private LocalDateTime registerDateTime;
	
	public Member(String email, String password,
				String name, LocalDateTime regDateTime) {
		this.email = email;
		this.password = password;
		this.name = name;
		this.registerDateTime = regDateTime;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getEmail() {
		return email;
	}

	public String getPassword() {
		return password;
	}

	public String getName() {
		return name;
	}

	public LocalDateTime getRegisterDateTime() {
		return registerDateTime;
	}
	
	public void changePassword(String oldPassword, String newPassword) {
		if (!password.equals(oldPassword))
			throw new WrongIdPasswordException();
		this.password = newPassword;
	}
	
	public boolean matchPassword(String password) {
		return this.password.equals(password);
	}

}
