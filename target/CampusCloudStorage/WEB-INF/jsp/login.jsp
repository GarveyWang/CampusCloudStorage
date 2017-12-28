<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>登录界面</title>
    <%@include file="common/head.jsp"%>
    <style>
        body {
            padding-top: 100px;
        }
    </style>
</head>
<body>
<div class="container">
    <div>${msg}</div>
    <form role="form" method="post" action="/account/login">
        <div class="row">
            <div class="col-md-4 col-md-offset-4 ">
                <h1>登录</h1>
            </div>
        </div>
        <br/>
        <div class="row">
            <div class="col-md-4 col-md-offset-4 ">
                <label>用户ID</label>
            </div>
        </div>
        <div class="row">
            <div class="col-md-4 col-md-offset-4 ">
                <input type="text" class="form-control" name="uId" placeholder="请输入用户ID">
            </div>
        </div>
        <%--<br/>--%>
        <div class="row">
            <div class="col-md-4 col-md-offset-4 ">
                <label>密码</label>
            </div>
        </div>
        <div class="row">
            <div class="col-md-4 col-md-offset-4 ">
                <input type="password" class="form-control" name="password" placeholder="请输入用户密码">
            </div>
        </div>
        <br/>
        <div class="row">
            <div class="col-md-4 col-md-offset-4 ">
                <button type="submit" class="btn btn-primary btn-block">登录</button>
            </div>
        </div>
    </form>

    <div class="row">
        <div class="col-md-4 col-md-offset-4 ">
            <form role="form" method="get" action="/account/register">
                <button type="submit" class="btn btn-default btn-block">注册</button>
            </form>
        </div>
    </div>
</div>


</body>

<%@include file="common/foot.jsp"%>

</html>