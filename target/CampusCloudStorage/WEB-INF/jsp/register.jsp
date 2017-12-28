<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>用户注册页面</title>
    <%@include file="common/head.jsp"%>
    <style>
        body {
            padding-top: 100px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div>
            ${msg}
        </div>
        <div class="row">
            <div class="col-md-4 col-md-offset-4 ">
                <h1>注册</h1>
            </div>
        </div>
        <br/>
        <form role="form" method="post" action="/account/register">
            <div class="row">
                <div class="col-md-4 col-md-offset-4 ">
                    <label>用户ID</label>
                </div>
            </div>
            <div class="row">
                <div class="col-md-4 col-md-offset-4 ">
                    <input type="text" class="form-control" id="u_id" name="uId" placeholder="请输入用户ID" value="${user.uId}">
                </div>
            </div>
            <div class="row">
                <div class="col-md-4 col-md-offset-4 ">
                    <label>用户名</label>
                </div>
            </div>
            <div class="row">
                <div class="col-md-4 col-md-offset-4 ">
                    <input type="text" class="form-control" id="name" name="name" placeholder="请输入用户名" value="${user.name}">
                </div>
            </div>
            <div class="row">
                <div class="col-md-4 col-md-offset-4 ">
                    <label>用户密码</label>
                </div>
            </div>
            <div class="row">
                <div class="col-md-4 col-md-offset-4 ">
                    <input type="password" class="form-control" id="password" name="password" placeholder="请输入用户密码" value="${user.password}">
                </div>
            </div>
            <div class="row">
                <div class="col-md-4 col-md-offset-4 ">
                    <label>账号类型</label>
                </div>
            </div>
            <div class="row">
                <div class="col-md-4 col-md-offset-4 ">
                    <select class="form-control" name="type">
                        <option value="PRIVATE">私人账号</option>
                        <option value="PUBLIC">公共账号</option>
                    </select>
                </div>
            </div>
            <br/>
            <div class="row">
                <div class="col-md-4 col-md-offset-4 ">
                    <button type="submit" class="btn btn-primary btn-block">注册</button>
                </div>
            </div>
        </form>
    </div>

</body>

<%@include file="common/foot.jsp"%>

</html>
