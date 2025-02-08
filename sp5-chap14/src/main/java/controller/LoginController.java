package controller;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import spring.AuthInfo;
import spring.AuthService;
import spring.WrongIdPasswordException;

@Controller
@RequestMapping("/login")
public class LoginController {
	private AuthService authService;

	public void setAuthService(AuthService authService) {
		this.authService = authService;
	}
	
	@GetMapping
	public String form(LoginCommand loginCommand,
			@CookieValue(value = "REMEMBER", required = false) Cookie rCookie ) {
		if (rCookie != null) {
			loginCommand.setEmail(rCookie.getValue());
			loginCommand.setRememberEmail(true);
		}
		return "login/loginForm";
	}
	
	@PostMapping
	public String submit(
			LoginCommand loginCommand, Errors errors, HttpSession session,
			HttpServletResponse response) {
		// 1. 유효성 검사
		new LoginCommandValidator().validate(loginCommand, errors);
		if (errors.hasErrors()) {
			return "login/loginForm";
		}
		try {
			// 2. 인증 절차 후 세션에 로그인정보 저장
			AuthInfo authInfo = authService.authenticate(
													loginCommand.getEmail(),
													loginCommand.getPassword());
			
			session.setAttribute("authInfo", authInfo);
			
			// 3. 쿠키 생성 후 response에 저장
			Cookie rememberCookie = new Cookie("REMEMBER", loginCommand.getEmail());
			rememberCookie.setPath("/");
			if (loginCommand.isRememberEmail()) { // '이메일 기억하기' 받아온 값이 true면
				rememberCookie.setMaxAge(60 * 60 * 24 * 30); // 30일 유지
			} else {
				rememberCookie.setMaxAge(0); // 바로 삭제
			}
			response.addCookie(rememberCookie);
			
			return "login/loginSuccess";
		} catch (WrongIdPasswordException e) {
			errors.reject("idPasswordNotMatching");
			return "login/loginForm";
		}
	}
}
