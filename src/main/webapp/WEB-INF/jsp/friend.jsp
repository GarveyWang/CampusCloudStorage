<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>好友</title>
    <%@include file="common/head.jsp"%>
    <%@include file="common/navbar.jsp"%>
</head>
<body>
<div class="container-fluid ">
    <div class="row">
        <div class="col-sm-3 col-md-2 sidebar">
            <ul class="nav nav-sidebar">
                <form role="form" id="form1" method="post" action="/home/${rootDir}">
                    <li>
                        <a href="#" onclick="$('#form1').submit();">
                            <span class="glyphicon glyphicon-home" aria-hidden="true"></span>
                            首页</a>
                    </li>
                </form>
                <form role="form"  id="form2" method="post" action="/friend/${uId}">
                    <li class="active">
                        <a id="active-a" href="#" onclick="$('#form2').submit();">
                            <span class="glyphicon glyphicon-user" aria-hidden="true"></span>
                            好友 <span class="sr-only">(current)</span></a>
                    </li>
                </form>
                <form role="form"  id="form3" method="post" action="/group/${uId}">
                    <li>
                        <a href="#" onclick="$('#form3').submit();">
                            <span class="glyphicon glyphicon-retweet" aria-hidden="true"></span>
                            群组</a>
                    </li>
                </form>
                <form role="form"  id="form4" method="post" action="/recyclebin/${recyclebin}">
                    <li>
                        <a href="#" onclick="$('#form4').submit();">
                            <span class="glyphicon glyphicon-trash" aria-hidden="true"></span>
                            回收站</a>
                    </li>
                </form>
            </ul>
        </div>
        <div class="col-sm-9 col-sm-offset-3 col-md-10 col-md-offset-2 main">
            <div class="container">
                <div>${msg}</div>
                <div class="tab-bar">
                    <ul id="myTab" class="nav nav-tabs">
                        <li class="active">
                            <a href="#first" data-toggle="tab">查找用户</a>
                        </li>
                    </ul>
                </div>
                <div id="myTabContent" class="tab-content">
                    <div class="tab-pane fade in active" id="first">
                        <form id="search_user_form" role="form" method="post" action="/friend/${uId}/search">
                            <div class="form-group form-inline">
                                <label>用户ID
                                    <input type="text" class="form-control" id="friend_id_input" placeholder="请输入用户ID" >
                                </label>
                                <button type="button" id="search_user_btn" class="btn btn-default btn-primary">查询</button>
                                <%--<button type="button" id="search_user_form_close_btn" class="btn btn-default">取消</button>--%>
                            </div>
                        </form>
                        <div id="search_result">
                        </div>
                    </div>
                </div>

                <%--<button id="search_user_form_open_btn" class="btn btn-default">查找用户</button>--%>





                <c:if test="${unpermittedFriendList.size()>0}">
                    <table class="table  table-hover table-condensed">
                        <caption>好友请求</caption>
                        <thead>
                        <tr>
                            <th>ID</th>
                            <th>名称</th>
                            <th>操作</th>
                        </tr>
                        </thead>
                        <tbody>
                        <c:forEach var="friend" items="${unpermittedFriendList}">
                            <tr>
                                <td>${friend.uId}</td>
                                <td>${friend.name}</td>
                                <td>
                                    <%--<div class="btn-group">--%>
                                        <%--<button class="btn btn-default agree_btn" friend_id="${friend.uId}">同意</button>--%>
                                        <%--<button class="btn btn-default delete_friend_btn" friend_id="${friend.uId}">拒绝</button>--%>
                                    <%--</div>--%>
                                        <a class="agree_btn" friend_id="${friend.uId}">同意</a>
                                        <a class="delete_friend_btn" friend_id="${friend.uId}">拒绝</a>

                                </td>
                            </tr>
                        </c:forEach>
                        </tbody>
                    </table>
                </c:if>

                <table class="table  table-hover table-condensed">
                    <caption>好友列表</caption>
                    <thead>
                    <tr>
                        <th>ID</th>
                        <th>姓名</th>
                        <th>操作</th>
                    </tr>
                    </thead>
                    <tbody>
                    <c:forEach var="friend" items="${friendList}">
                        <tr>
                            <td>${friend.uId}</td>
                            <td>${friend.name}</td>
                            <td>
                                <%--<div class="btn-group">--%>
                                    <%--<button class="btn btn-default share_btn" friend_id="${friend.uId}">查看共享文件</button>--%>
                                    <%--<button class="btn btn-default delete_friend_btn" friend_id="${friend.uId}">删除朋友</button>--%>
                                <%--</div>--%>
                                    <a class="share_btn" friend_id="${friend.uId}">查看共享文件</a>
                                    <a class="delete_friend_btn" friend_id="${friend.uId}">删除朋友</a>

                            </td>
                        </tr>
                    </c:forEach>
                    </tbody>
                </table>

            </div>
        </div>
    </div>
</div>

</div>

</body>

<%@include file="common/foot.jsp"%>

<script type="text/javascript">
    $(function () {
        $('.agree_btn').click(function () {
            var u_id=${uId};
            var friend_id=$(this).attr('friend_id');
            var action='/friend/' + u_id + '/' + friend_id + '/agree' ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            var u_id_input = $('<input type="text" name="uId" />');
            u_id_input.attr('value',u_id);
            var friend_id_input = $('<input type="text" name="friendId" />');
            friend_id_input.attr('value',friend_id);

            form.append(u_id_input);
            form.append(friend_id_input);

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

        $('.delete_friend_btn').click(function () {
            var u_id=${uId};
            var friend_id=$(this).attr('friend_id');
            var action='/friend/' + u_id + '/' + friend_id + '/delete' ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            var u_id_input = $('<input type="text" name="uId" />');
            u_id_input.attr('value',u_id);
            var friend_id_input = $('<input type="text" name="friendId" />');
            friend_id_input.attr('value',friend_id);

            form.append(u_id_input);
            form.append(friend_id_input);

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

        //查询好友
        $('#search_user_form_open_btn').click(function () {
            $('#search_user_form').show();
            $(this).hide();
        })

        $('#search_user_form_close_btn').click(function () {
            $('#search_user_form_open_btn').show();
            $('#msg').hide();
        })

        $('#search_user_btn').click(function () {
            var friend_id = $("#friend_id_input").val();
            if(isNaN(friend_id)){
                alert("用户ID非法");
                return false;
            }

            var htmlobj=$.ajax({
                url:"/friend/${uId}/"+friend_id+"/search",
                data:{
                    uId:${uId},
                    friendId:friend_id
                },
                async:false,
                dataType: "text",
                contentType: "application/x-www-form-urlencoded;charset=UTF-8",
                type:"POST"
            });
            $("#search_result").html(htmlobj.responseText);
        })

        //添加好友 （ajax返回的button）
        $(document).delegate('#friend_request_btn','click',function(){
            var friend_id=$(this).attr('friend_id');
            var action='/friend/${uId}/' + friend_id + '/request' ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

        $('.share_btn').click(function () {
            var u_id=${uId};
            var friend_id=$(this).attr('friend_id');
            var action='/file/' + u_id + '/' + friend_id + '/friendshare' ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            var u_id_input = $('<input type="text" name="uId" />');
            u_id_input.attr('value',u_id);
            var friend_id_input = $('<input type="text" name="friendId" />');
            friend_id_input.attr('value',friend_id);

            form.append(u_id_input);
            form.append(friend_id_input);

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

    })

</script>

</html>