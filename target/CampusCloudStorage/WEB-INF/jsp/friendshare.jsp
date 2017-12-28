<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>好友分享文件</title>
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
                <div class="return" id="friend-return">
                    <form role="form" id="form5" method="post" action="/friend/${uId}">
                        <a href="#" onclick="$('#form5').submit();">
                            <span class="glyphicon glyphicon-menu-left" aria-hidden="true"></span>
                            返回
                        </a>
                    </form>
                </div>
                <div class="tab-bar">
                    <ul id="myTab" class="nav nav-tabs">
                        <li class="active">
                            <a href="#first" data-toggle="tab">我分享的文件</a>
                        </li>
                        <li>
                            <a href="#second" data-toggle="tab">好友分享的文件</a>
                        </li>
                    </ul>
                </div>
                <div id="myTabContent" class="tab-content">
                    <div class="tab-pane fade in active" id="first">
                        <table class="table">
                            <thead>
                            <tr>
                                <th>文件ID</th>
                                <th>文件名</th>
                                <th>大小</th>
                                <th>分享备注</th>
                                <th>操作</th>
                            </tr>
                            </thead>
                            <tbody>
                            <c:forEach var="file" items="${mySharedList}">
                                <tr>
                                    <td>${file.fileHeader.fId}</td>
                                    <td>${file.fileHeader.name}</td>
                                    <td>${file.fileHeader.size}</td>
                                    <td>${file.userFileShare.remark}</td>
                                    <td>
                                        <%--<div class="btn-group">--%>
                                            <a class="my_shared_file_delete_btn" f_id="${file.fileHeader.fId}">取消分享</a>
                                        <%--</div>--%>
                                    </td>
                                </tr>
                            </c:forEach>
                            </tbody>
                        </table>
                    </div>
                    <div class="tab-pane fade" id="second">
                        <table class="table">
                            <thead>
                            <tr>
                                <th>文件ID</th>
                                <th>文件名</th>
                                <th>大小</th>
                                <th>分享备注</th>
                                <th>操作</th>
                            </tr>
                            </thead>
                            <tbody>
                            <c:forEach var="file" items="${friendSharedList}">
                                <tr>
                                    <td>${file.fileHeader.fId}</td>
                                    <td>${file.fileHeader.name}</td>
                                    <td>${file.fileHeader.size}</td>
                                    <td>${file.userFileShare.remark}</td>
                                    <td>
                                        <%--<div class="btn-group">--%>
                                            <a class="friend_shared_file_download_btn" f_id="${file.fileHeader.fId}">下载</a>
                                        <%--</div>--%>
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
</div>
</body>

<%@include file="common/foot.jsp"%>

<script type="text/javascript">
    $(function () {
        $('.friend_shared_file_download_btn').click(function () {
            var f_id=$(this).attr('f_id');
            var action='/file/' + f_id + '/download' ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            var f_id_input = $('<input type="text" name="fId" />');
            f_id_input.attr('value',f_id);

            form.append(f_id_input);

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

        $('.my_shared_file_delete_btn').click(function(){
            var f_id=$(this).attr('f_id');
            var action='/file/' + ${uId} + '/' + ${friendId} + '/' + f_id + '/deletefriendshare' ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            var f_id_input = $('<input type="text" name="fId" />');
            f_id_input.attr('value',f_id);

            form.append(f_id_input);

            form.appendTo("body").submit();
            form.remove();
            return false;
        })
    })

</script>

</html>