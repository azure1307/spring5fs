<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
	<title><spring:message code="login.title" /></title>
</head>
<body>
	<p>
		<spring:message code="login.done" />
	</p>
	<p>
		<a href="<c:url value='/main' />">
			[<spring:message code="go.main" />]
		</a>
	</p>
</body>
</html>