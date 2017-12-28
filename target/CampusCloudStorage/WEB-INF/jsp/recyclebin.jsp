<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>主页</title>
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
                    <li>
                        <a href="#" onclick="$('#form2').submit();">
                            <span class="glyphicon glyphicon-user" aria-hidden="true"></span>
                            好友</a>
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
                    <li  class="active">
                        <a id="active-a" href="#" onclick="$('#form4').submit();">
                            <span class="glyphicon glyphicon-trash" aria-hidden="true"></span>
                            回收站 <span class="sr-only">(current)</span></a>
                    </li>
                </form>
            </ul>
        </div>

        <div class="col-sm-9 col-sm-offset-3 col-md-10 col-md-offset-2 main">
            <div class="container">
                <div>${msg}</div>

                <div class="path">
                    当前路径:
                    <c:forEach var="dir" items="${pathList}">
                        <span class="path_span" d_id="${dir.dId}"> ${dir.name}> </span>
                    </c:forEach>
                </div>

                <table class="table   table-hover table-condensed" width="100%">
                    <thead>
                    <tr>
                        <th>ID</th>
                        <th>名称</th>
                        <th>大小</th>
                        <th>创建/上传日期</th>
                        <th>操作</th>
                    </tr>
                    </thead>
                    <tbody>
                    <c:forEach var="dir" items="${dirList}">
                        <tr>
                            <td>${dir.dId}</td>
                            <td><span class="glyphicon glyphicon-folder-open icon-grey" style="color: rgb(180,180,180);" aria-hidden="true"></span> ${dir.name}</td>
                            <td>-</td>
                            <td>${dir.createTime}</td>
                            <td>
                                <a class="dir_open_btn" d_id="${dir.dId}">打开</a>
                                <a class="dir_recover_form_open_btn" d_id="${dir.dId}"  data-toggle="modal" data-target="#bin-dir-recover-modal">恢复至</a>
                                <a class="dir_delete_btn" d_id="${dir.dId}">彻底删除</a>
                            </td>
                        </tr>
                    </c:forEach>
                    <c:forEach var="file" items="${fileHeaderList}">
                        <tr>
                            <td width="5%">${file.fId}</td>
                            <td width="25%"><span class="glyphicon glyphicon-file icon-grey" style="color: rgb(180,180,180);" aria-hidden="true"></span> ${file.name}</td>
                            <td width="5%">${file.size} B</td>
                            <td width="25%">${file.submitTime}</td>
                            <td width="40%">
                                <a class="file_delete_btn" f_id="${file.fId}">彻底删除</a>
                                <a class="file_recover_form_open_btn" f_id="${file.fId}" data-toggle="modal" data-target="#bin-file-recover-modal">恢复至</a>
                            </td>
                        </tr>
                    </c:forEach>
                    </tbody>
                </table>

                <div class="modal fade" id="bin-dir-recover-modal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
                    <div class="modal-dialog" role="document">
                        <div class="modal-content">
                            <div class="modal-body">
                                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                                <br/>
                                <form id="dir_recover_form" role="form" method="post">
                                    <h3>选择移入文件夹</h3>
                                    <ul class="list-group" id="dir_move_list">
                                    </ul>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal fade" id="bin-file-recover-modal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
                    <div class="modal-dialog" role="document">
                        <div class="modal-content">
                            <div class="modal-body">
                                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                                <br/>

                                <form id="file_recover_form" role="form" method="post">
                                    <h3>选择移入文件夹</h3>
                                    <ul class="list-group" id="file_move_list">
                                    </ul>
                                </form>
                            </div>
                        </div>
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
        var src_d_id;
        var src_f_id;

        $('#dir_recover_form').hide();
        $('#file_recover_form').hide();


        //删除文件
        $('.file_delete_btn').click(function () {
            var f_id=$(this).attr('f_id');
            var action='/file/' + f_id + '/delete' ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            var f_id_input = $('<input type="text" name="fId" />');

            form.append(f_id_input);

            form.appendTo("body").submit();
            form.remove();
            return false;
        })


        //删除文件夹
        $('.dir_delete_btn').click(function () {
            var d_id=$(this).attr('d_id');
            var action='/recyclebin/' + d_id + '/dir/delete' ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            var d_id_input = $('<input type="text" name="dId" />');
            d_id_input.attr('value',d_id);

            form.append(d_id_input);

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

        //路径显示
        $('.path_span').click(function () {
            var d_id=$(this).attr('d_id');
            var action='/recyclebin/' + d_id ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            var d_id_input = $('<input type="text" name="dId" />');
            d_id_input.attr('value',d_id);

            form.append(d_id_input);

            form.appendTo("body").submit();
            form.remove();
            return false;
        })

        $('.dir_open_btn').click(function () {
            var d_id=$(this).attr('d_id');
            var action='/recyclebin/' + d_id ;
            var form = $('<form></form>');

            form.attr('action', action);
            form.attr('method', 'post');
            form.attr('target', '_self');

            var d_id_input = $('<input type="text" name="dId" />');
            d_id_input.attr('value',d_id);

            form.append(d_id_input);

            form.appendTo("body").submit();
            form.remove();
            return false;
        })


        //恢复文件夹 ajax
        $('.dir_recover_form_open_btn').click(function () {
            src_d_id = $(this).attr('d_id');
            var action="/recyclebin/"+src_d_id+"/dir/";
            $('#dir_recover_form').attr("action",action);
            $('#dir_recover_form').show();

            var htmlobj=$.ajax({
                url:"/home/"+src_d_id+"/dir/${rootDir}/enter",
                data:{
                    srcId:src_d_id,
                    dId:${rootDir},
                    moveType:"dir"
                },
                async:false,
                dataType: "text",
                contentType: "application/x-www-form-urlencoded;charset=UTF-8",
                type:"POST"
            });
            $("#dir_move_list").html(htmlobj.responseText);
//            $(this).hide();
        })

        $(document).delegate('.dir_move_enter_btn','click',function () {
            var htmlobj=$.ajax({
                url:"/home/"+src_d_id+"/dir/"+$(this).attr("d_id")+"/enter",
                data:{
                    srcDId:src_d_id,
                    dId:$(this).attr("d_id"),
                    moveType:"dir"
                },
                async:false,
                dataType: "text",
                contentType: "application/x-www-form-urlencoded;charset=UTF-8",
                type:"POST"
            });
            $("#dir_move_list").html(htmlobj.responseText);
        })

//        $(document).delegate('#dir_recover_form_close_btn','click',function () {
//            $('#dir_recover_form').hide();
//            $('.dir_recover_form_open_btn').show();
//        })

        $(document).delegate('#dir_move_back_btn','click',function () {
            var htmlobj=$.ajax({
                url:"/home/"+src_d_id+"/dir/"+$(this).attr("d_id")+"/enter",
                data:{
                    srcDId:src_d_id,
                    dId:$(this).attr("d_id"),
                    moveType:"dir"
                },
                async:false,
                dataType: "text",
                contentType: "application/x-www-form-urlencoded;charset=UTF-8",
                type:"POST"
            });
            $("#dir_move_list").html(htmlobj.responseText);
        })

        $(document).delegate('#dir_move_btn','click',function () {
            var parentId = $(this).attr("d_id");
            var action = $("#dir_recover_form").attr("action")+parentId+"/recover";
            $("#dir_recover_form").attr("action",action);
            $("#dir_recover_form").submit();
        })

        //恢复文件 ajax
        $('.file_recover_form_open_btn').click(function () {
            src_f_id = $(this).attr('f_id');
            var action="/recyclebin/"+src_f_id+"/file/";
            $('#file_recover_form').attr("action",action);
            $('#file_recover_form').show();

            var htmlobj=$.ajax({
                url:"/home/"+src_f_id+"/dir/${rootDir}/enter",
                data:{
                    srcId:src_f_id,
                    dId:${rootDir},
                    moveType:"file"
                },
                async:false,
                dataType: "text",
                contentType: "application/x-www-form-urlencoded;charset=UTF-8",
                type:"POST"
            });
            $("#file_move_list").html(htmlobj.responseText);
//            $(this).hide();
        })

        $(document).delegate('.file_move_enter_btn','click',function () {
            var htmlobj=$.ajax({
                url:"/home/"+src_f_id+"/dir/"+$(this).attr("d_id")+"/enter",
                data:{
                    srcId:src_f_id,
                    dId:$(this).attr("d_id"),
                    moveType:"file"
                },
                async:false,
                dataType: "text",
                contentType: "application/x-www-form-urlencoded;charset=UTF-8",
                type:"POST"
            });
            $("#file_move_list").html(htmlobj.responseText);
        })

        $(document).delegate('#file_move_form_close_btn','click',function () {
//            $('#file_move_form').hide();
//            $('.file_recover_form_open_btn').show();

        })

        $(document).delegate('#file_move_btn','click',function () {
            var parentId = $(this).attr("d_id");
            var action = $("#file_recover_form").attr("action")+parentId+"/recover";
            $("#file_recover_form").attr("action",action);
            $("#file_recover_form").submit();
        })

        $(document).delegate('#file_move_back_btn','click',function () {
            var htmlobj=$.ajax({
                url:"/home/"+src_f_id+"/dir/"+$(this).attr("d_id")+"/enter",
                data:{
                    srcId:src_f_id,
                    dId:$(this).attr("d_id"),
                    moveType:"file"
                },
                async:false,
                dataType: "text",
                contentType: "application/x-www-form-urlencoded;charset=UTF-8",
                type:"POST"
            });
            $("#file_move_list").html(htmlobj.responseText);
        })
    })

</script>

</html>
