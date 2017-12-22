<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>群组</title>
    <%@include file="common/head.jsp"%>
</head>
<body>
<div class="container">
    <div>${msg}</div>

    <div class="btn-group">
        <button id="create_group_form_open_btn" class="btn btn-default">创建群组</button>
        <button id="search_group_form_open_btn" class="btn btn-default">查找群组</button>
    </div>

    <form id="create_group_form" role="form" method="post" action="/group/${uId}/addgroup">
        <div class="form-group form-inline">
            <label>群组名
                <input type="text" class="form-control" name="name" placeholder="请输入群组名" >
            </label>
            <label>类型
                <select class="form-control" name="type">
                    <option value="PRIVATE" selected="selected">私密群组</option>
                    <option value="PUBLIC">公开群组</option>
                </select>
            </label>
            <button type="submit" class="btn btn-default">新建群组</button>
            <button type="button" id="create_group_form_close_btn" class="btn btn-default">取消</button>
        </div>
    </form>

    <form id="search_group_form" role="form" method="post" action="/group/${uId}/search">
        <div class="form-group form-inline">
            <label>群组ID
                <input type="text" class="form-control" id="group_id_input" placeholder="请输入群组ID" >
            </label>
            <button type="button" id="search_group_btn" class="btn btn-default">查询</button>
            <button type="button" id="search_group_form_close_btn" class="btn btn-default">取消</button>
        </div>
    </form>

    <div id="search_result">
    </div>


    <table class="table">
        <caption>我创建的群组列表</caption>
        <thead>
        <tr>
            <th>ID</th>
            <th>名称</th>
            <th>群组类型</th>
            <th>操作</th>
        </tr>
        </thead>
        <tbody>
        <c:forEach var="group" items="${ownedGroupList}">
            <tr>
                <td>${group.gId}</td>
                <td>${group.name}</td>
                <td>${group.type}</td>
                <td>
                    <div class="btn-group">
                        <button class="btn btn-default detail_group_btn" group_id="${group.gId}">查看详情</button>
                        <button class="btn btn-default delete_group_btn" group_id="${group.gId}">解散群组</button>
                    </div>
                </td>
            </tr>
        </c:forEach>
        </tbody>
    </table>

    <table class="table">
        <caption>我加入的群组列表</caption>
        <thead>
        <tr>
            <th>ID</th>
            <th>名称</th>
            <th>操作</th>
        </tr>
        </thead>
        <tbody>
        <c:forEach var="group" items="${joinedGroupList}">
            <tr>
                <td>${group.gId}</td>
                <td>${group.name}</td>
                <td>
                    <div class="btn-group">
                        <button class="btn btn-default detail_group_btn" group_id="${group.gId}">查看详情</button>
                        <button class="btn btn-default quit_group_btn" group_id="${group.gId}">退出群组</button>
                    </div>
                </td>
            </tr>
        </c:forEach>
        </tbody>
    </table>

</div>
</body>

<%@include file="common/foot.jsp"%>

<script type="text/javascript">
    $(function () {
        $('#search_group_form').hide();
        $('#create_group_form').hide();


        //创建群组
        $('#create_group_form_open_btn').click(function () {
            $('#create_group_form').show();
            $(this).hide();
        })

        $('#create_group_form_close_btn').click(function () {
            $('#create_group_form').hide();
            $('#create_group_form_open_btn').show();
        })

        //查询群组
        $('#search_group_form_open_btn').click(function () {
            $('#search_group_form').show();
            $(this).hide();
        })

        $('#search_group_form_close_btn').click(function () {
            $('#search_group_form').hide();
            $('#search_group_form_open_btn').show();
        })

        $('#search_group_btn').click(function () {
            var g_id = $("#group_id_input").val();
            if(isNaN(g_id)){
                alert("群组ID非法");
                return false;
            }

            var htmlobj=$.ajax({
                url:"/group/${uId}/"+g_id+"/search",
                data:{
                    uId:${uId},
                    gId:g_id
                },
                async:false,
                dataType: "text",
                contentType: "application/x-www-form-urlencoded;charset=UTF-8",
                type:"POST"
            });
            $("#search_result").html(htmlobj.responseText);
        })

        //申请群组 （ajax返回的button）
        $(document).delegate('#group_request_btn','click',function(){
            var g_id=$(this).attr('g_id');
            var action='/group/${uId}/' + g_id + '/request' ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

        //群组详情
        $('.detail_group_btn').click(function () {
            var u_id=${uId};
            var g_id=$(this).attr('group_id');
            var action='/group/' + u_id + '/' + g_id;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            var u_id_input = $('<input type="text" name="uId" />');
            u_id_input.attr('value',u_id);
            var g_id_input = $('<input type="text" name="gId" />');
            g_id_input.attr('value',g_id);

            form.append(u_id_input);
            form.append(g_id_input);

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

        //退出群组
        $('.quit_group_btn').click(function () {
            var g_id=$(this).attr('group_id');
            var action='/group/${uId}/' + g_id +'/${uId}/delete';
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

        //解散群组
        $('.delete_group_btn').click(function () {
            var g_id=$(this).attr('group_id');
            var action='/group/${uId}' + '/' + g_id  +'/deletegroup';
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            form.appendTo("body").submit();
            form.remove();
            return false;
        })
    })

</script>

</html>