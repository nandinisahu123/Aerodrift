import ast

def generate_revoke_code(finding: dict) -> str:
    # AST is used to construct the call rather than concatenating Python source.
    call = ast.Call(
        func=ast.Attribute(value=ast.Name(id="ec2", ctx=ast.Load()),
                           attr="revoke_security_group_ingress", ctx=ast.Load()),
        args=[],
        keywords=[
            ast.keyword(arg="GroupId", value=ast.Constant(finding["security_group"])),
            ast.keyword(arg="IpPermissions", value=ast.List(elts=[
                ast.Dict(keys=[
                    ast.Constant("IpProtocol"),
                    ast.Constant("FromPort"),
                    ast.Constant("ToPort"),
                    ast.Constant("IpRanges")
                ], values=[
                    ast.Constant(finding["protocol"]),
                    ast.Constant(finding["port"]),
                    ast.Constant(finding["port"]),
                    ast.List(elts=[ast.Dict(
                        keys=[ast.Constant("CidrIp")],
                        values=[ast.Constant(finding["source"])]
                    )], ctx=ast.Load())
                ])
            ], ctx=ast.Load()))
        ]
    )
    tree = ast.fix_missing_locations(ast.Module(
        body=[ast.Expr(value=call)], type_ignores=[]
    ))
    return ast.unparse(tree)
