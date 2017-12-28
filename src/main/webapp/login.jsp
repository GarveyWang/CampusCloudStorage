<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>登录界面</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta charset="UTF-8">
    <!-- 引入 Bootstrap -->
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">

    <%--<link href="${pageContext.request.contextPath}/resources/css/bootstrap.min.css" rel="stylesheet">--%>

    <!-- HTML5 Shiv 和 Respond.js 用于让 IE8 支持 HTML5元素和媒体查询 -->
    <!-- 注意： 如果通过 file://  引入 Respond.js 文件，则该文件无法起效果 -->
    <!--[if lt IE 9]>
    <script src="https://oss.maxcdn.com/libs/html5shiv/3.7.0/html5shiv.js"></script>
    <script src="https://oss.maxcdn.com/libs/respond.js/1.3.0/respond.min.js"></script>
    <![endif]-->
    <style>
        .btn {
            border-radius: 15px;
        }
        .btn-primary {
            background-color: #28BB9C;
            border: none;
        }
        .btn-primary:hover {
            background-color: #74D3BF;
        }
        .btn-primary:focus {
            background-color: #74D3BF;
        }
        h1 {
            color: #28BB9C;
        }
    </style>

    <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
</head>
<body>
<div class="container">
    <br/><br/><br/><br/><br/>
    <div>${msg}</div>
    <form id="login_form" role="form" method="post" action="/account/login">
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
                <input id="u_id" type="text" class="form-control" name="uId" placeholder="请输入用户ID">
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
                <input id="password" type="password" class="form-control" name="password" placeholder="请输入用户密码">
            </div>
        </div>
        <br/>
        <div class="row">
            <div class="col-md-4 col-md-offset-4 ">
                <button id="login_btn" type="button" class="btn btn-primary btn-block">登录</button>
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

<script type="text/javascript" src="${pageContext.request.contextPath}/resources/js/jquery-3.2.1.min.js"></script>

<script type="text/javascript" src="${pageContext.request.contextPath}/resources/js/bootstrap.min.js"></script>

<script type="text/javascript">
    $(function () {
        $('#login_btn').click(function () {
            //var oldPassword = $('#password').val();
            //var newPassword = "4";
            //$("#password").val(newPassword);
            $('#login_form').submit();
        })
    })
</script>

</html>