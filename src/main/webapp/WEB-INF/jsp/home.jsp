<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>主页</title>
    <%@include file="common/head.jsp"%>
    <%@include file="common/navbar.jsp"%>
</head>
<body>

<div class="container-fluid">
    <div class="row">
        <div class="col-sm-3 col-md-2 sidebar">
            <ul class="nav nav-sidebar">
                <form role="form" id="form1" method="post" action="/home/${rootDir}">
                    <li class="active">
                        <a id="active-a" href="#" onclick="$('#form1').submit();">
                            <span class="glyphicon glyphicon-home" aria-hidden="true"></span>
                             首页 <span class="sr-only">(current)</span></a>
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
                    <li>
                        <a href="#" onclick="$('#form4').submit();">
                            <span class="glyphicon glyphicon-trash" aria-hidden="true"></span>
                             回收站</a>
                    </li>
                </form>
            </ul>
        </div>


        <div class="col-sm-9 col-sm-offset-3 col-md-9 col-md-offset-2 main">
            <div class="container">

                <div class="path">
                    当前路径:
                    <c:forEach var="dir" items="${pathList}">
                        <span class="path_span" d_id="${dir.dId}"> ${dir.name} </span>
                    </c:forEach>
                </div>
                <br/>
                <div class="tab-bar">
                    <ul id="myTab" class="nav nav-tabs">
                        <li class="active">
                            <a href="#first" data-toggle="tab">新建文件夹</a>
                        </li>
                        <li>
                            <a href="#second" data-toggle="tab">上传文件</a>
                        </li>
                    </ul>
                </div>
                <div id="myTabContent" class="tab-content">
                    <div class="tab-pane fade in active" id="first">
                        <form id="dir_create_form" role="form" method="post" action="/home/${currentDir}/dir/add">
                            <label>文件夹名</label>
                            <div class="form-inline">
                                <input type="text" class="form-control" name="name" placeholder="请输入文件夹名" >
                                <button type="submit" class="btn btn-default  btn-primary">新建</button>
                            </div>
                        </form>
                    </div>
                    <div class="tab-pane fade" id="second">
                        <form id="file_upload_form" action="/file/upload" method="post" enctype="multipart/form-data">
                            <label>选择文件</label>
                            <div class="form-inline">
                            <input type="file" class="file" name="file"  multiplewidth="120px" />
                            </div>
                        </form>
                    </div>
                </div>

                <div>${msg}</div>

                <table class="table table-hover table-condensed" width="100%">
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
                            <td><span class="glyphicon glyphicon-folder-open" style="color: rgb(180,180,180);" aria-hidden="true"></span> ${dir.name}</td>
                            <td>-</td>
                            <td>${dir.createTime}</td>
                            <td>
                                    <a class="dir_open_btn" d_id="${dir.dId}" >打开</a>
                                    <a class="dir_rename_form_open_btn" d_id="${dir.dId}" name="${dir.name}" data-toggle="modal" data-target="#home-dir-rename-modal">重命名</a>
                                    <a class="dir_move_form_open_btn" d_id="${dir.dId}" data-toggle="modal" data-target="#home-dir-move-modal">移动至</a>
                                    <a class="dir_remove_btn" d_id="${dir.dId}">删除</a>
                            </td>
                        </tr>
                    </c:forEach>
                    <c:forEach var="file" items="${fileHeaderList}">
                        <tr>
                            <td width="5%">${file.fId}</td>
                            <td width="25%"><span class="glyphicon glyphicon-file"  style="color: rgb(180,180,180);" aria-hidden="true"></span> ${file.name}</td>
                            <td width="5%">${file.size}B</td>
                            <td width="25%">${file.submitTime}</td>
                            <td width="40%">
                                <a class="file_remove_btn" f_id="${file.fId}">删除</a>
                                <a class="file_download_btn" f_id="${file.fId}">下载</a>
                                <a class="file_move_form_open_btn" f_id="${file.fId}"  data-toggle="modal" data-target="#home-file-move-modal">移动至</a>
                                <a class="friend_share_form_open_btn" f_id="${file.fId}"  data-toggle="modal" data-target="#home--file-friend-share-modal">分享给好友</a>
                                <a class="group_share_form_open_btn" f_id="${file.fId}"  data-toggle="modal" data-target="#home-file-group-share-modal">分享到群组</a>
                            </td>
                        </tr>
                    </c:forEach>
                    </tbody>
                </table>
                <div class="modal fade" id="home-dir-rename-modal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
                    <div class="modal-dialog" role="document">
                        <div class="modal-content">
                            <div class="modal-body">
                                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                                <br/><br/>
                                <form id="dir_rename_form" role="form" method="post">
                                    <div class="form-group form-inline">
                                        <label>文件夹名
                                            <input type="text" id="rename_input" class="form-control" name="name" placeholder="请输入文件夹名" >
                                        </label>
                                        <button type="submit" class="btn btn-default">重命名</button>
                                        <button type="button" id="dir_rename_form_close_btn" class="btn btn-default" data-dismiss="modal">取消</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal fade" id="home-dir-move-modal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
                    <div class="modal-dialog" role="document">
                        <div class="modal-content">
                            <div class="modal-body">
                                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                                <br/><br/>
                                <form id="dir_move_form" role="form" method="post">
                                    <h3>选择移入文件夹</h3>
                                    <ul class="list-group" id="dir_move_list">
                                    </ul>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal fade" id="home-file-move-modal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
                    <div class="modal-dialog" role="document">
                        <div class="modal-content">
                            <div class="modal-body">
                                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                                <br/><br/>
                                <form id="file_move_form" role="form" method="post">
                                    <h3>选择移入文件夹</h3>
                                    <ul class="list-group" id="file_move_list">
                                    </ul>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal fade" id="home--file-friend-share-modal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
                    <div class="modal-dialog" role="document">
                        <div class="modal-content">
                            <div class="modal-body">
                                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                                <br/><br/>
                                <form id="friend_share_form" role="form" method="post">
                                    <h3>选择好友</h3>
                                    <select class="form-control" id="friend_id_select" name="friendId">
                                        <c:forEach var="friend" items="${friendList}">
                                            <option value="${friend.uId}">(${friend.uId}) ${friend.name}</option>
                                        </c:forEach>
                                    </select>
                                    <input class="form-control" name="remark" placeholder="请输入备注">
                                    <button type="button" id="friend_share_btn" class="btn btn-default">分享</button>
                                    <button type="button" id="friend_share_form_close_btn" class="btn btn-default" data-dismiss="modal">取消</button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal fade" id="home-file-group-share-modal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel">
                    <div class="modal-dialog" role="document">
                        <div class="modal-content">
                            <div class="modal-body">
                                <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                                <br/><br/>
                                <form id="group_share_form" role="form" method="post">
                                    <h3>选择群组</h3>
                                    <select class="form-control" id="group_id_select" name="gId">
                                        <c:forEach var="group" items="${groupList}">
                                            <option value="${group.gId}">(${group.gId}) ${group.name}</option>
                                        </c:forEach>
                                    </select>
                                    <input class="form-control" name="remark" placeholder="请输入备注">
                                    <button type="button" id="group_share_btn" class="btn btn-default">分享</button>
                                    <button type="button" id="group_share_form_close_btn" class="btn btn-default" data-dismiss="modal">取消</button>
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

//        $('#dir_create_form').hide();
        $('#dir_rename_form').hide();
        $('#dir_move_form').hide();
        $('#file_move_form').hide();
//        $('#file_upload_form').hide();
        $('#friend_share_form').hide();
        $('#group_share_form').hide();

        //上传文件
//        $('#file_upload_form_open_btn').click(function () {
//            $('#file_upload_form').show();
//            $('#dir_create_form').hide();
////            $(this).hide();
//        })

//        $('#form_upload_form_close_btn').click(function () {
//            $('#file_upload_form').hide();
//            $('#file_upload_form_open_btn').show();
//        })

        //下载文件
        $('.file_download_btn').click(function () {
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

        //删除文件
        $('.file_remove_btn').click(function () {
            var f_id=$(this).attr('f_id');
            var action='/file/' + f_id + '/remove' ;
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

        //新建文件夹
//        $('#dir_create_form_open_btn').click(function () {
//            $('#dir_create_form').show();
//            $('#file_upload_form').hide();
////            $(this).hide();
////            $(this).css("background-color","black");
//        })

//        $('#dir_create_form_close_btn').click(function () {
//            $('#dir_create_form').hide();
//            $('#dir_create_form_open_btn').show();
//        })

        //删除文件夹
        $('.dir_remove_btn').click(function () {
            var d_id=$(this).attr('d_id');
            var action='/home/' + d_id + '/dir/remove' ;
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
            var action='/home/' + d_id ;
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
            var action='/home/' + d_id ;
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

        //重命名
        $('.dir_rename_form_open_btn').click(function () {
            $('#rename_input').val($(this).attr('name'));
            var action="/home/"+$(this).attr('d_id')+"/dir/rename";
            $('#dir_rename_form').attr("action",action);
            $('#dir_rename_form').show();
//            $(this).hide();
        })

//        $('#dir_rename_form_close_btn').click(function () {
//            $('#dir_rename_form').hide();
//            $('#dir_rename_form_open_btn').show();
//        })

        //移动文件夹 ajax
        $('.dir_move_form_open_btn').click(function () {
            src_d_id = $(this).attr('d_id');
            var action="/home/"+src_d_id+"/dir/";
            $('#dir_move_form').attr("action",action);
            $('#dir_move_form').show();

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

//        $(document).delegate('#dir_move_form_close_btn','click',function () {
////            $('#dir_move_form').hide();
////            $('.dir_move_form_open_btn').show();
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
            var action = $("#dir_move_form").attr("action")+parentId+"/move";
            $("#dir_move_form").attr("action",action);
            $("#dir_move_form").submit();
        })

        //移动文件 ajax
        $('.file_move_form_open_btn').click(function () {
            src_f_id = $(this).attr('f_id');
            var action="/home/"+src_f_id+"/file/";
            $('#file_move_form').attr("action",action);
            $('#file_move_form').show();

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

//        $(document).delegate('#file_move_form_close_btn','click',function () {
//            $('#file_move_form').hide();
//            $('.file_move_form_open_btn').show();
//        })

//        $(document).delegate('#file_move_back_btn','click',function () {
//            var htmlobj=$.ajax({
//                url:"/home/"+src_d_id+"/dir/"+$(this).attr("d_id")+"/enter",
//                data:{
//                    srcDId:src_d_id,
//                    dId:$(this).attr("d_id"),
//                    moveType:"file"
//                },
//                async:false,
//                dataType: "text",
//                contentType: "application/x-www-form-urlencoded;charset=UTF-8",
//                type:"POST"
//            });
//            $("#dir_move_list").html(htmlobj.responseText);
//        })
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

        $(document).delegate('#file_move_btn','click',function () {
            var parentId = $(this).attr("d_id");
            var action = $("#file_move_form").attr("action")+parentId+"/move";
            $("#file_move_form").attr("action",action);
            $("#file_move_form").submit();
        })

        //分享朋友
        $('.friend_share_form_open_btn').click(function () {
            $('#friend_share_form').show();
            $('#friend_share_form').attr('f_id',$(this).attr('f_id'));
//            $(this).hide();
        })

//        $('#friend_share_form_close_btn').click(function () {
//            $('#friend_share_form').hide();
//            $('.friend_share_form_open_btn').show();
//        })

        $('#friend_share_btn').click(function () {
            var friend_id=$('#friend_id_select').val();
            if(isNaN(friend_id)){
                alert("请选择一个好友！");
                return false;
            }
            var f_id = $('#friend_share_form').attr('f_id');
            var action = '/file/${uId}/' + friend_id + '/' + f_id + '/friendshare';
            $('#friend_share_form').attr('action',action);

            $('#friend_share_form').submit();
            return false;
        })

        //分享至群组
        $('.group_share_form_open_btn').click(function () {
            $('#group_share_form').show();
            $('#group_share_form').attr('f_id',$(this).attr('f_id'));
//            $(this).hide();
        })

//        $('#group_share_form_close_btn').click(function () {
//            $('#group_share_form').hide();
//            $('.group_share_form_open_btn').show();
//        })

        $('#group_share_btn').click(function () {
            var g_id=$('#group_id_select').val();
            if(isNaN(g_id)){
                alert("请选择一个群组！");
                return false;
            }
            var f_id = $('#group_share_form').attr('f_id');
            var action = '/group/${uId}/' + g_id + '/' + f_id + '/groupshare';
            $('#friend_share_form').attr('action',action);

            $('#friend_share_form').submit();
            return false;
        })
    })

</script>

</html>
