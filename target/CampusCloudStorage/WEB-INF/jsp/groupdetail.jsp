<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>群组详情</title>
    <%@include file="common/head.jsp"%>
    <%@include file="common/navbar.jsp"%>
</head>
<body>
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
                <li>
                    <a href="#" onclick="$('#form2').submit();">
                        <span class="glyphicon glyphicon-user" aria-hidden="true"></span>
                        好友</a>
                </li>
            </form>
            <form role="form"  id="form3" method="post" action="/group/${uId}">
                <li class="active">
                    <a id="active-a" href="#" onclick="$('#form3').submit();">
                        <span class="glyphicon glyphicon-retweet" aria-hidden="true"></span>
                        群组 <span class="sr-only">(current)</span></a>
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
            <div class="return" id="group-return">
                <form role="form" id="form5" method="post" action="/group/${uId}">
                        <a href="#" onclick="$('#form5').submit();">
                            <span class="glyphicon glyphicon-menu-left" aria-hidden="true"></span>
                            返回
                        </a>
                </form>
            </div>
            <div>${msg}</div>
            <div class="tab-bar">
                <ul id="myTab" class="nav nav-tabs">
                    <li class="active">
                        <a href="#first" data-toggle="tab">群组成员</a>
                    </li>
                    <li>
                        <a href="#second" data-toggle="tab">群组分享的文件</a>
                    </li>
                </ul>
            </div>
            <div id="myTabContent" class="tab-content">
                <div class="tab-pane fade in active" id="first">
                    <table class="table">
                        <caption>群组成员</caption>
                        <thead>
                        <tr>
                            <th>成员ID</th>
                            <th>姓名</th>
                            <c:if test="${uId==owner.uId}">
                                <th>操作</th>
                            </c:if>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td>${owner.uId}</td>
                            <td>${owner.name}（群主）</td>
                        </tr>
                        <c:forEach var="member" items="${memberList}">
                            <tr>
                                <td>${member.uId}</td>
                                <td>${member.name}</td>
                                <c:if test="${uId==owner.uId}">
                                    <td>
                                        <%--<div class="btn-group">--%>
                                            <a class="delete_member_btn" member_id="${member.uId}">踢出群组</a>
                                        <%--</div>--%>
                                    </td>
                                </c:if>
                            </tr>
                        </c:forEach>
                        </tbody>
                    </table>
                </div>
                <div class="tab-pane fade" id="second">
                    <table class="table">
                        <caption>群组共享的文件</caption>
                        <thead>
                        <tr>
                            <th>文件ID</th>
                            <th>文件名</th>
                            <th>大小</th>
                            <th>分享者ID</th>
                            <th>分享者姓名</th>
                            <th>分享备注</th>
                            <th>操作</th>
                        </tr>
                        </thead>
                        <tbody>
                        <c:forEach var="file" items="${groupFileShareList}">
                            <tr>
                                <td>${file.fileHeader.fId}</td>
                                <td>${file.fileHeader.name}</td>
                                <td>${file.fileHeader.size}</td>
                                <td>${file.provider.uId}</td>
                                <td>${file.provider.name}</td>
                                <td>${file.groupFileShare.remark}</td>
                                <td>
                                    <%--<div class="btn-group">--%>
                                        <a class="download_file_btn" f_id="${file.fileHeader.fId}">下载</a>
                                        <c:if test="${file.provider.uId==uId||owner.uId==uId}">
                                            <a class="group_shared_file_delete_btn" f_id="${file.fileHeader.fId}">取消分享</a>
                                        </c:if>
                                    <%--</div>--%>
                                </td>
                            </tr>
                        </c:forEach>
                        </tbody>
                    </table>

                </div>
            </div>


            <c:if test="${unpermittedMemberList.size()>0}">
                <table class="table">
                    <caption>加群请求</caption>
                    <thead>
                    <tr>
                        <th>ID</th>
                        <th>姓名</th>
                        <th>操作</th>
                    </tr>
                    </thead>
                    <tbody>
                    <c:forEach var="member" items="${unpermittedMemberList}">
                        <tr>
                            <td>${member.uId}</td>
                            <td>${member.name}</td>
                            <td>
                                <div class="btn-group">
                                    <button class="btn btn-default permit_member_btn" member_id="${member.uId}">同意</button>
                                    <button class="btn btn-default refuse_member_btn" member_id="${member.uId}">拒绝</button>
                                </div>
                            </td>
                        </tr>
                    </c:forEach>
                    </tbody>
                </table>
            </c:if>






        </div>

    </div>
</div>

</body>

<%@include file="common/foot.jsp"%>

<script type="text/javascript">
    $(function () {
        $('.permit_member_btn').click(function () {
            var member_id=$(this).attr('member_id');
            var action='/group/${uId}/${gId}/' + member_id + '/permit' ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

        $('.refuse_member_btn').click(function () {
            var member_id=$(this).attr('member_id');
            var action='/group/${uId}/${gId}/' + member_id + '/refuse' ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

        $('.delete_member_btn').click(function () {
            var member_id=$(this).attr('member_id');
            var action='/group/${uId}/${gId}/' + member_id + '/delete' ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            var u_id_input = $('<input type="text" name="uId" />');
            u_id_input.attr('value',${uId});
            var g_id_input = $('<input type="text" name="gId" />');
            g_id_input.attr('value',${gId});
            var member_id_input = $('<input type="text" name="memberId" />');
            member_id_input.attr('value',member_id);

            form.append(u_id_input);
            form.append(g_id_input);
            form.append(member_id_input);

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

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

        $('.group_shared_file_delete_btn').click(function(){
            var f_id=$(this).attr('f_id');
            var action='/group/${uId}/${gId}/' +  f_id + '/deletegroupshare' ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

        //文件下载
        $('.download_file_btn').click(function () {
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
    })

</script>

</html>